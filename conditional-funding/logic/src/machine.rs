//! Collection state machine (funding spec §Состояния, §Таблица переходов,
//! §Тайминги).
//!
//! Time is applied before the action (lazily); a late call doesn't help the
//! action, but the accrued time transition persists. Borders are strict `>=`
//! (the boundary instant belongs to the next phase). All time arithmetic is
//! `checked`; an unrepresentable instant is `Overflow` and leaves the state
//! untouched.

use crate::verdict::verdict;
use crate::MIN_VOTE_WEIGHT;

/// Terminal outcome. `Refund` returns every escrow to its donor; `Settle` pays
/// them all through the splitter and mints reputation to each donor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Settle,
    Refund,
}

/// Collection state. Birth is always `Funding` with empty votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Funding,
    Voting { started_at: u64 },
    Decided { outcome: Outcome },
}

/// A reputation-weighted vote (validity checked in `inspect_message`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub voter: [u8; 32],
    pub weight: u128,
    pub done: bool,
}

/// Actions on a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Ready,
    RecipientCancel,
    Vote(Vote),
    Tick,
}

/// Errors of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepError {
    InvalidTransition,
    WeightBelowThreshold,
    DuplicateVoter,
    Overflow,
}

/// A materialized collection: state, accrued votes, and the immutable anchors
/// (`created_at` = the first funded escrow's birth slot→time; `duration`,
/// `voting_period`; the verdict's `quorum_weight` + `approval_threshold`, snapped
/// from the collection's `id` preimage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    pub state: State,
    pub votes: Vec<Vote>,
    pub created_at: u64,
    pub duration: u64,
    pub voting_period: u64,
    pub quorum_weight: u128,
    pub approval_threshold: u16,
}

impl Collection {
    /// End of the funding window: `created_at + duration`.
    fn funding_end(&self) -> Result<u64, StepError> {
        self.created_at
            .checked_add(self.duration)
            .ok_or(StepError::Overflow)
    }
}

/// One step: accrued time transitions, then the action. A rejected action keeps
/// the advanced state; a time-arithmetic overflow returns `Overflow` and leaves
/// the state untouched.
pub fn step(c: &mut Collection, action: Action, now: u64) -> Result<(), StepError> {
    advance(c, now)?;
    apply_action(c, action, now)
}

/// Apply accrued time transitions.
fn advance(c: &mut Collection, now: u64) -> Result<(), StepError> {
    match c.state {
        State::Funding => {
            if now >= c.funding_end()? {
                c.state = State::Decided {
                    outcome: Outcome::Refund,
                };
            }
        }
        State::Voting { started_at } => {
            let voting_end = started_at
                .checked_add(c.voting_period)
                .ok_or(StepError::Overflow)?;
            if now >= voting_end {
                c.state = State::Decided {
                    outcome: verdict(&c.votes, c.quorum_weight, c.approval_threshold),
                };
            }
        }
        State::Decided { .. } => {}
    }
    Ok(())
}

impl State {
    /// Whether this state admits `action` by the transition table alone — the
    /// **time-free** half of `apply_action`'s verdict, for the boundary
    /// (`games-harness.md §6`). Same mechanism and same soundness argument as
    /// `conditional_tasks_logic::State::admits`.
    ///
    /// Safe against the **stored**, un-advanced state: the only move time can
    /// make is into `Decided` (see `advance`), and `Decided` admits nothing. So a
    /// `false` here is doomed in every state time could have produced. A `true` is
    /// a filter, not a verdict — the update still advances the clock and `Vote`
    /// still owes its threshold and dedup.
    pub fn admits(self, action: &Action) -> bool {
        matches!(
            (self, action),
            (_, Action::Tick)
                | (State::Funding, Action::Ready | Action::RecipientCancel)
                | (State::Voting { .. }, Action::Vote(_))
        )
    }
}

/// Apply an action to the (already advanced) state. Exhaustive, no `_ =>`.
fn apply_action(c: &mut Collection, action: Action, now: u64) -> Result<(), StepError> {
    match (c.state, action) {
        (_, Action::Tick) => Ok(()),

        (State::Funding, Action::Ready) => {
            c.state = State::Voting { started_at: now };
            Ok(())
        }
        (State::Funding, Action::RecipientCancel) => {
            c.state = State::Decided {
                outcome: Outcome::Refund,
            };
            Ok(())
        }
        (State::Voting { .. }, Action::Vote(v)) => {
            if v.weight < MIN_VOTE_WEIGHT {
                return Err(StepError::WeightBelowThreshold);
            }
            if c.votes.iter().any(|e| e.voter == v.voter) {
                return Err(StepError::DuplicateVoter);
            }
            c.votes.push(v);
            Ok(())
        }

        (State::Funding, Action::Vote(_)) => Err(StepError::InvalidTransition),
        (State::Voting { .. }, Action::Ready | Action::RecipientCancel) => {
            Err(StepError::InvalidTransition)
        }
        (State::Decided { .. }, Action::Ready | Action::RecipientCancel | Action::Vote(_)) => {
            Err(StepError::InvalidTransition)
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic, not the hot path
mod tests {
    use super::*;

    const CREATED: u64 = 1_000;
    const DUR: u64 = 600;
    const VP: u64 = 120;
    const Q: u128 = 150_000;
    const T: u16 = 5_000;

    fn collection(state: State, votes: Vec<Vote>) -> Collection {
        Collection {
            state,
            votes,
            created_at: CREATED,
            duration: DUR,
            voting_period: VP,
            quorum_weight: Q,
            approval_threshold: T,
        }
    }

    fn vote(voter: u8, weight: u128, done: bool) -> Vote {
        Vote {
            voter: [voter; 32],
            weight,
            done,
        }
    }

    /// `State::admits` and `apply_action` are two readings of one transition
    /// table: the boundary trusts the first, the update obeys the second. Drift
    /// is the exposure — a `true` the update refuses is a doomed call billed to
    /// the canister, a `false` it would have accepted is a valid call silently
    /// dropped. Enumerated over every pair, not sampled.
    #[test]
    fn admits_agrees_with_apply_action_on_every_pair() {
        let states = [
            State::Funding,
            State::Voting {
                started_at: CREATED,
            },
            State::Decided {
                outcome: Outcome::Settle,
            },
            State::Decided {
                outcome: Outcome::Refund,
            },
        ];
        let actions = [
            Action::Ready,
            Action::RecipientCancel,
            Action::Vote(vote(1, MIN_VOTE_WEIGHT, true)),
            Action::Tick,
        ];
        for s in states {
            for a in &actions {
                let mut c = collection(s, Vec::new());
                // Clock pinned before every window so `advance` cannot fire and
                // only the action's own verdict is compared.
                let applied = step(&mut c, a.clone(), CREATED);
                assert_eq!(
                    s.admits(a),
                    applied != Err(StepError::InvalidTransition),
                    "state {s:?} × action {a:?}: admits() and apply_action disagree"
                );
            }
        }
    }

    fn funding_end() -> u64 {
        CREATED + DUR
    }

    #[test]
    fn ready_opens_voting_within_the_window() {
        let mut c = collection(State::Funding, vec![]);
        assert_eq!(step(&mut c, Action::Ready, funding_end() - 1), Ok(()));
        assert_eq!(
            c.state,
            State::Voting {
                started_at: funding_end() - 1
            }
        );
    }

    #[test]
    fn recipient_cancel_refunds_from_funding() {
        let mut c = collection(State::Funding, vec![]);
        assert_eq!(step(&mut c, Action::RecipientCancel, 0), Ok(()));
        assert_eq!(
            c.state,
            State::Decided {
                outcome: Outcome::Refund
            }
        );
    }

    #[test]
    fn funding_border_is_strict() {
        // One second before the end → ready works.
        let mut early = collection(State::Funding, vec![]);
        assert_eq!(step(&mut early, Action::Ready, funding_end() - 1), Ok(()));
        // Exactly at the end → refunded, ready rejected (and the tick persists).
        let mut late = collection(State::Funding, vec![]);
        assert_eq!(
            step(&mut late, Action::Ready, funding_end()),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            late.state,
            State::Decided {
                outcome: Outcome::Refund
            }
        );
    }

    #[test]
    fn vote_only_in_voting_dedup_and_threshold() {
        let mut c = collection(State::Voting { started_at: 0 }, vec![]);
        assert_eq!(
            step(&mut c, Action::Vote(vote(1, MIN_VOTE_WEIGHT - 1, true)), 0),
            Err(StepError::WeightBelowThreshold)
        );
        assert_eq!(
            step(&mut c, Action::Vote(vote(1, 200_000, true)), 0),
            Ok(())
        );
        assert_eq!(
            step(&mut c, Action::Vote(vote(1, 200_000, false)), 0),
            Err(StepError::DuplicateVoter)
        );
        assert_eq!(c.votes.len(), 1);
        // Vote from Funding is invalid.
        let mut f = collection(State::Funding, vec![]);
        assert_eq!(
            step(&mut f, Action::Vote(vote(1, 200_000, true)), 0),
            Err(StepError::InvalidTransition)
        );
    }

    #[test]
    fn voting_tally_finalizes_with_quorum() {
        // Past voting_end with a quorum-meeting yes majority → Settle.
        let mut c = collection(
            State::Voting { started_at: 0 },
            vec![vote(1, Q, true), vote(2, MIN_VOTE_WEIGHT, false)],
        );
        let voting_end = VP; // started_at 0 + VP
        let late = Action::Vote(vote(3, MIN_VOTE_WEIGHT, false));
        assert_eq!(
            step(&mut c, late, voting_end),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            c.state,
            State::Decided {
                outcome: Outcome::Settle
            }
        );
        assert_eq!(c.votes.len(), 2, "the late vote is not counted");
    }

    #[test]
    fn silence_settles() {
        // Voting window closes with no votes → settle. An inquorate vote no longer
        // protects the donor; stopping the payout takes a quorate "no".
        let mut c = collection(State::Voting { started_at: 0 }, vec![]);
        assert_eq!(step(&mut c, Action::Tick, VP), Ok(()));
        assert_eq!(
            c.state,
            State::Decided {
                outcome: Outcome::Settle
            }
        );
    }

    #[test]
    fn decided_is_absorbing() {
        for a in [
            Action::Ready,
            Action::RecipientCancel,
            Action::Vote(vote(1, Q, true)),
        ] {
            let mut c = collection(
                State::Decided {
                    outcome: Outcome::Settle,
                },
                vec![],
            );
            assert_eq!(step(&mut c, a, 0), Err(StepError::InvalidTransition));
            assert_eq!(
                c.state,
                State::Decided {
                    outcome: Outcome::Settle
                }
            );
        }
    }

    #[test]
    fn overflow_leaves_state_untouched() {
        let mut c = Collection {
            state: State::Funding,
            votes: vec![],
            created_at: u64::MAX,
            duration: 1,
            voting_period: VP,
            quorum_weight: Q,
            approval_threshold: T,
        };
        assert_eq!(step(&mut c, Action::Ready, 0), Err(StepError::Overflow));
        assert_eq!(c.state, State::Funding);
    }

    #[test]
    fn voting_rejects_ready_and_cancel() {
        // After `ready` there is no door back: ready/recipient_cancel in Voting are
        // rejected and the state holds (the "cancel only from Funding" invariant).
        for a in [Action::Ready, Action::RecipientCancel] {
            let mut c = collection(State::Voting { started_at: 0 }, vec![]);
            assert_eq!(step(&mut c, a, 1), Err(StepError::InvalidTransition));
            assert_eq!(c.state, State::Voting { started_at: 0 });
        }
    }

    #[test]
    fn recipient_cancel_after_deadline_is_refund_then_rejected() {
        // At the funding deadline the accrued tick refunds first; the
        // recipient_cancel then lands on Decided → InvalidTransition.
        let mut c = collection(State::Funding, vec![]);
        assert_eq!(
            step(&mut c, Action::RecipientCancel, funding_end()),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            c.state,
            State::Decided {
                outcome: Outcome::Refund
            }
        );
    }

    #[test]
    fn voting_side_overflow_leaves_state_untouched() {
        // The Funding-side overflow is tested above; here the Voting-side clock
        // (`started_at + voting_period`) overflow → Overflow, state untouched.
        let mut c = Collection {
            state: State::Voting {
                started_at: u64::MAX,
            },
            voting_period: 1,
            ..collection(State::Funding, vec![])
        };
        assert_eq!(step(&mut c, Action::Tick, 0), Err(StepError::Overflow));
        assert_eq!(
            c.state,
            State::Voting {
                started_at: u64::MAX
            }
        );
    }

    #[test]
    fn a_vote_at_the_last_instant_is_accepted() {
        // Lower boundary: a vote at `voting_end − 1` is still in Voting and counts
        // (the tally happens only at `>= voting_end`).
        let mut c = collection(State::Voting { started_at: 0 }, vec![]);
        assert_eq!(
            step(&mut c, Action::Vote(vote(1, 200_000, true)), VP - 1),
            Ok(())
        );
        assert_eq!(c.state, State::Voting { started_at: 0 });
        assert_eq!(c.votes.len(), 1);
    }
}
