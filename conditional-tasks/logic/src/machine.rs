//! Task state machine (tasks spec §Состояния, §Таблица переходов, §Тайминги).
//!
//! `step` applies accrued time transitions (`advance`) first, then the action;
//! a rejected action still persists the time transition (a failed action ≡ a
//! `Tick`). All time arithmetic is `checked`; an unrepresentable instant is
//! `Overflow` and leaves the state untouched.

use crate::verdict::verdict;
use crate::{DEADLINE_MARGIN, MIN_VOTE_WEIGHT};

/// Terminal outcome. `Cancel` frees the donor; `Settle` pays the recipient and
/// mints reputation to the donor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Settle,
    Cancel,
}

/// Task state. `Created` — text visible only to the recipient; `Accepted` —
/// text public; `Voting` — reputation-weighted window; `Decided` — absorbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Created,
    Accepted,
    Voting { started_at: i64 },
    Decided { outcome: Outcome },
}

/// A reputation-weighted vote. Validity (signature + weight proof + threshold)
/// is checked in `inspect_message`, before the paid update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub voter: [u8; 32],
    pub weight: u128,
    pub done: bool,
}

/// Actions on a task. `Tick` applies only accrued time transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Accept,
    Decline,
    Ready,
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

/// A materialized task: state, accrued votes, and the immutable time anchors
/// (`deadline` from the escrow, `voting_period` baked into `task_id`). The
/// windows (`cutoff`, `voting_end`) are pure functions of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub state: State,
    pub votes: Vec<Vote>,
    pub deadline: i64,
    pub voting_period: i64,
}

impl Task {
    /// End of the accept/ready window: `deadline − voting_period − margin`.
    fn cutoff(&self) -> Result<i64, StepError> {
        self.deadline
            .checked_sub(self.voting_period)
            .and_then(|t| t.checked_sub(DEADLINE_MARGIN))
            .ok_or(StepError::Overflow)
    }

    /// End of the voting window: `deadline − margin`.
    fn voting_end(&self) -> Result<i64, StepError> {
        self.deadline
            .checked_sub(DEADLINE_MARGIN)
            .ok_or(StepError::Overflow)
    }
}

/// One step: accrued time transitions, then the action. A rejected action keeps
/// the advanced state (the time transition persists); a time-arithmetic overflow
/// returns `Overflow` and leaves the state untouched.
pub fn step(task: &mut Task, action: Action, now: i64) -> Result<(), StepError> {
    advance(task, now)?;
    apply_action(task, action, now)
}

/// Apply accrued time transitions (spec §Таблица переходов, «Временные»).
fn advance(task: &mut Task, now: i64) -> Result<(), StepError> {
    match task.state {
        State::Created | State::Accepted => {
            if now >= task.cutoff()? {
                task.state = State::Decided {
                    outcome: Outcome::Cancel,
                };
            }
        }
        State::Voting { .. } => {
            if now >= task.voting_end()? {
                task.state = State::Decided {
                    outcome: verdict(&task.votes),
                };
            }
        }
        State::Decided { .. } => {}
    }
    Ok(())
}

/// Apply an action to the (already advanced) state. Exhaustive, no `_ =>`.
fn apply_action(task: &mut Task, action: Action, now: i64) -> Result<(), StepError> {
    match (task.state, action) {
        // Time-only: the transition already happened in `advance`.
        (_, Action::Tick) => Ok(()),

        (State::Created, Action::Accept) => {
            task.state = State::Accepted; // text revealed
            Ok(())
        }
        (State::Created, Action::Decline) | (State::Accepted, Action::Decline) => {
            task.state = State::Decided {
                outcome: Outcome::Cancel,
            };
            Ok(())
        }
        (State::Accepted, Action::Ready) => {
            task.state = State::Voting { started_at: now };
            Ok(())
        }
        (State::Voting { .. }, Action::Vote(v)) => {
            if v.weight < MIN_VOTE_WEIGHT {
                return Err(StepError::WeightBelowThreshold);
            }
            if task.votes.iter().any(|e| e.voter == v.voter) {
                return Err(StepError::DuplicateVoter);
            }
            task.votes.push(v);
            Ok(())
        }

        // Everything else is an invalid transition (exhaustive).
        (State::Created, Action::Ready | Action::Vote(_)) => Err(StepError::InvalidTransition),
        (State::Accepted, Action::Accept | Action::Vote(_)) => Err(StepError::InvalidTransition),
        (State::Voting { .. }, Action::Accept | Action::Decline | Action::Ready) => {
            Err(StepError::InvalidTransition)
        }
        (
            State::Decided { .. },
            Action::Accept | Action::Decline | Action::Ready | Action::Vote(_),
        ) => Err(StepError::InvalidTransition),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A deadline far enough that the windows are positive: cutoff = D - VP - MARGIN.
    const VP: i64 = 120;
    const D: i64 = 1_000_000;

    fn task(state: State, votes: Vec<Vote>) -> Task {
        Task {
            state,
            votes,
            deadline: D,
            voting_period: VP,
        }
    }

    fn vote(voter: u8, weight: u128, done: bool) -> Vote {
        Vote {
            voter: [voter; 32],
            weight,
            done,
        }
    }

    fn cutoff() -> i64 {
        D - VP - DEADLINE_MARGIN
    }
    fn voting_end() -> i64 {
        D - DEADLINE_MARGIN
    }

    #[test]
    fn created_accepts_and_reveals_then_ready_opens_voting() {
        let mut t = task(State::Created, vec![]);
        assert_eq!(step(&mut t, Action::Accept, 0), Ok(()));
        assert_eq!(t.state, State::Accepted);
        assert_eq!(step(&mut t, Action::Ready, 42), Ok(()));
        assert_eq!(t.state, State::Voting { started_at: 42 });
    }

    #[test]
    fn decline_cancels_from_created_and_from_accepted() {
        let mut a = task(State::Created, vec![]);
        assert_eq!(step(&mut a, Action::Decline, 0), Ok(()));
        assert_eq!(
            a.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );

        let mut b = task(State::Accepted, vec![]);
        assert_eq!(step(&mut b, Action::Decline, 0), Ok(()));
        assert_eq!(
            b.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );
    }

    #[test]
    fn double_accept_is_invalid_and_keeps_accepted() {
        let mut t = task(State::Accepted, vec![]);
        assert_eq!(
            step(&mut t, Action::Accept, 0),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(t.state, State::Accepted);
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        // Ready/Vote from Created.
        let mut t = task(State::Created, vec![]);
        assert_eq!(
            step(&mut t, Action::Ready, 0),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            step(&mut t, Action::Vote(vote(1, MIN_VOTE_WEIGHT, true)), 0),
            Err(StepError::InvalidTransition)
        );
        // Vote from Accepted.
        let mut a = task(State::Accepted, vec![]);
        assert_eq!(
            step(&mut a, Action::Vote(vote(1, MIN_VOTE_WEIGHT, true)), 0),
            Err(StepError::InvalidTransition)
        );
        // Accept/Decline/Ready from Voting (all three, per the exhaustive arm).
        let mut v = task(State::Voting { started_at: 0 }, vec![]);
        assert_eq!(
            step(&mut v, Action::Accept, 0),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            step(&mut v, Action::Decline, 0),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            step(&mut v, Action::Ready, 0),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(v.state, State::Voting { started_at: 0 });
    }

    #[test]
    fn decided_is_absorbing() {
        for action in [
            Action::Accept,
            Action::Decline,
            Action::Ready,
            Action::Vote(vote(1, MIN_VOTE_WEIGHT, true)),
        ] {
            let mut t = task(
                State::Decided {
                    outcome: Outcome::Settle,
                },
                vec![],
            );
            assert_eq!(step(&mut t, action, 0), Err(StepError::InvalidTransition));
            assert_eq!(
                t.state,
                State::Decided {
                    outcome: Outcome::Settle
                }
            );
        }
        // A Tick on Decided is a no-op success.
        let mut t = task(
            State::Decided {
                outcome: Outcome::Cancel,
            },
            vec![],
        );
        assert_eq!(step(&mut t, Action::Tick, i64::MAX), Ok(()));
        assert_eq!(
            t.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );
    }

    #[test]
    fn accept_boundary_at_cutoff_is_exact() {
        // One second before cutoff → accepts.
        let mut early = task(State::Created, vec![]);
        assert_eq!(step(&mut early, Action::Accept, cutoff() - 1), Ok(()));
        assert_eq!(early.state, State::Accepted);

        // Exactly at cutoff → already cancelled (advance fires), accept rejected.
        let mut late = task(State::Created, vec![]);
        assert_eq!(
            step(&mut late, Action::Accept, cutoff()),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            late.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );
    }

    #[test]
    fn failed_action_is_a_tick() {
        // Past cutoff, Accept fails — but the accrued Cancel persists.
        let mut t = task(State::Created, vec![]);
        assert_eq!(
            step(&mut t, Action::Accept, cutoff()),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            t.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );
    }

    #[test]
    fn vote_after_window_tallies_first_then_rejects() {
        // Voting past voting_end with a winning done majority → tally to Settle,
        // and the late vote is rejected on the now-Decided state.
        let mut t = task(
            State::Voting { started_at: 0 },
            vec![
                vote(1, 3 * MIN_VOTE_WEIGHT, true),
                vote(2, MIN_VOTE_WEIGHT, false),
            ],
        );
        let late = Action::Vote(vote(3, MIN_VOTE_WEIGHT, false));
        assert_eq!(
            step(&mut t, late, voting_end()),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            t.state,
            State::Decided {
                outcome: Outcome::Settle
            }
        );
        assert_eq!(t.votes.len(), 2, "the late vote is not counted");
    }

    #[test]
    fn voting_end_boundary_is_exact() {
        // One second before → still Voting, vote accepted.
        let mut t = task(State::Voting { started_at: 0 }, vec![]);
        assert_eq!(
            step(
                &mut t,
                Action::Vote(vote(1, MIN_VOTE_WEIGHT, true)),
                voting_end() - 1
            ),
            Ok(())
        );
        assert_eq!(t.state, State::Voting { started_at: 0 });
        assert_eq!(t.votes.len(), 1);
    }

    #[test]
    fn votes_dedup_and_threshold() {
        let mut t = task(State::Voting { started_at: 0 }, vec![]);
        // Below threshold → rejected, no count.
        assert_eq!(
            step(&mut t, Action::Vote(vote(1, MIN_VOTE_WEIGHT - 1, true)), 0),
            Err(StepError::WeightBelowThreshold)
        );
        assert!(t.votes.is_empty());
        // First real vote counts.
        assert_eq!(
            step(&mut t, Action::Vote(vote(1, MIN_VOTE_WEIGHT, true)), 0),
            Ok(())
        );
        // Same voter again → duplicate, no count.
        assert_eq!(
            step(&mut t, Action::Vote(vote(1, MIN_VOTE_WEIGHT, false)), 0),
            Err(StepError::DuplicateVoter)
        );
        assert_eq!(t.votes.len(), 1);
    }

    #[test]
    fn time_overflow_leaves_state_untouched() {
        // deadline = i64::MIN makes cutoff/voting_end underflow.
        let mut t = Task {
            state: State::Created,
            votes: vec![],
            deadline: i64::MIN,
            voting_period: VP,
        };
        assert_eq!(step(&mut t, Action::Accept, 0), Err(StepError::Overflow));
        assert_eq!(t.state, State::Created, "overflow must not move the state");
    }

    #[test]
    fn voting_end_overflow_leaves_state_untouched() {
        // The Created path (cutoff) is tested above; here the Voting path
        // (`voting_end = deadline − margin`) underflows → Overflow, state untouched.
        let mut t = Task {
            state: State::Voting { started_at: 0 },
            votes: vec![],
            deadline: i64::MIN,
            voting_period: VP,
        };
        assert_eq!(step(&mut t, Action::Tick, 0), Err(StepError::Overflow));
        assert_eq!(t.state, State::Voting { started_at: 0 });
    }
}
