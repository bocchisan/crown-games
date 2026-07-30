//! Auction state machine (auction spec §Состояния, §Таблица переходов,
//! §Трёхступенчатое разрешение).
//!
//! Time is applied **before** the action (lazily); a late call doesn't help the
//! action, but the accrued time transition persists. Time boundaries are absolute
//! (`created_at + duration [+ perform_window]`). `Bidding` has **no** time
//! transition: registration is frozen at `T = created_at + duration` (a guard in
//! the register/accept/return arms), but the state holds until the recipient
//! `pick_winner`s (→ `Performing`) or `cancel`s (→ `Done{None}`); a stuck auction
//! holds no money — each escrow exits `refund()` by its `deadline`. All time
//! arithmetic is `checked`; an unrepresentable instant is `Overflow` and leaves
//! the state untouched.

use crate::verdict::verdict;
use crate::MIN_VOTE_WEIGHT;

/// Terminal outcome of a contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Settle,
    Cancel,
}

/// Auction state. `Done { winner: None }` = no winner (recipient `cancel`, or the
/// window closed and no one was picked — escrows exit via `refund()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Bidding,
    Performing,
    Voting { started_at: u64 },
    Done { winner: Option<Outcome> },
}

/// A reputation-weighted vote (validity checked in `inspect_message`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub voter: [u8; 32],
    pub weight: u128,
    pub done: bool,
}

/// Actions (auction spec §Таблица переходов). `return_*` carry the target's role
/// (a loser lot is auto-cancelled in `Performing`; only the winner may be returned
/// there). `PickWinner` names the recipient's chosen lot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    RegisterEntry,
    AcceptLot,
    ReturnLot { is_winner: bool },
    ReturnEntry { is_winner_lot: bool },
    PickWinner { lot_id: [u8; 32] },
    CancelAuction,
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

/// The auction as a state machine: state + immutable timing anchors (`created_at`
/// = the first confirmed entry's birth slot→time; `duration`/`perform_window`/
/// `voting_period` snapped from the `auction_id` preimage), the recipient-picked
/// `winner_lot`, and the winning lot's accrued `votes` (only the winner lot is
/// ever in `Voting`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auction {
    pub state: State,
    pub created_at: u64,
    pub duration: u64,
    pub perform_window: u64,
    pub voting_period: u64,
    pub winner_lot: Option<[u8; 32]>,
    pub votes: Vec<Vote>,
}

impl Auction {
    /// End of the bidding window (`T`): registration freezes here.
    fn bidding_end(&self) -> Result<u64, StepError> {
        self.created_at
            .checked_add(self.duration)
            .ok_or(StepError::Overflow)
    }
    fn perform_end(&self) -> Result<u64, StepError> {
        self.bidding_end()?
            .checked_add(self.perform_window)
            .ok_or(StepError::Overflow)
    }
}

/// One step: accrued time transitions, then the action. A rejected action keeps
/// the advanced state; a time-arithmetic overflow returns `Overflow` and leaves
/// the state untouched.
pub fn step(a: &mut Auction, action: Action, now: u64) -> Result<(), StepError> {
    advance(a, now)?;
    apply_action(a, action, now)
}

/// Apply accrued time transitions. `Bidding` has none (registration freezes at
/// `T` via the action guard; the state is left by `pick_winner`/`cancel`).
fn advance(a: &mut Auction, now: u64) -> Result<(), StepError> {
    match a.state {
        State::Bidding => {}
        State::Performing => {
            if now >= a.perform_end()? {
                a.state = State::Done {
                    winner: Some(Outcome::Cancel),
                };
            }
        }
        State::Voting { started_at } => {
            let voting_end = started_at
                .checked_add(a.voting_period)
                .ok_or(StepError::Overflow)?;
            if now >= voting_end {
                a.state = State::Done {
                    winner: Some(verdict(&a.votes)),
                };
            }
        }
        State::Done { .. } => {}
    }
    Ok(())
}

/// The *kind* of an action, without the parameters the canister derives from
/// stored state (`is_winner`, `is_winner_lot`, `lot_id`). The boundary knows the
/// kind from the signed `action` field alone — the flags are the update's job,
/// which is exactly why [`State::admits`] is expressed over kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    RegisterEntry,
    AcceptLot,
    ReturnLot,
    ReturnEntry,
    PickWinner,
    CancelAuction,
    Ready,
    Vote,
}

impl State {
    /// Whether this state admits **any** action of `kind` — the time-free,
    /// parameter-free half of `apply_action`'s verdict, for the boundary
    /// (`games-harness.md §6`).
    ///
    /// Conservative on two axes, and it has to be on both:
    ///
    /// - **Time.** Answered against the stored, un-advanced state. `Bidding`
    ///   never leaves itself by the clock; `Performing`/`Voting` leave only for
    ///   `Done`, which admits nothing; and the `open` guard inside `Bidding` only
    ///   ever goes true → false. So no action becomes admissible later, and a
    ///   `false` here is doomed for every `now`.
    /// - **Parameters.** `ReturnLot`/`ReturnEntry` carry a winner flag the
    ///   canister reads from state, so a kind is admitted if *some* flag would
    ///   be — the boundary must not guess the flag and refuse a valid call.
    ///
    /// A `true` is therefore a filter, never a verdict: the update still advances
    /// the clock, resolves the flags, and may refuse. A `false` is exact.
    pub fn admits(&self, kind: ActionKind) -> bool {
        use ActionKind as K;
        match self {
            State::Bidding => matches!(
                kind,
                K::RegisterEntry
                    | K::AcceptLot
                    | K::ReturnLot
                    | K::ReturnEntry
                    | K::PickWinner
                    | K::CancelAuction
            ),
            // The winner lot may be returned, and its entries with it; `ready`
            // opens voting. Nothing else survives the bidding window.
            State::Performing => matches!(kind, K::Ready | K::ReturnLot | K::ReturnEntry),
            State::Voting { .. } => matches!(kind, K::Vote),
            State::Done { .. } => false,
        }
    }
}

/// Apply an action to the (already advanced) state. `register`/`accept`/`return`
/// are lot bookkeeping the canister performs; the machine gates them by state
/// **and** the bidding window (`now < T`). `pick_winner`/`cancel` stay open while
/// `Bidding`, before or after `T`.
fn apply_action(a: &mut Auction, action: Action, now: u64) -> Result<(), StepError> {
    // Registration open: still `Bidding` and before the bidding-window close `T`.
    let open = matches!(a.state, State::Bidding) && now < a.bidding_end()?;
    match (&a.state, action) {
        (_, Action::Tick) => Ok(()),

        (State::Bidding, Action::RegisterEntry | Action::AcceptLot) if open => Ok(()),
        (State::Bidding, Action::ReturnLot { is_winner: false }) if open => Ok(()),
        (State::Bidding, Action::ReturnEntry { .. }) if open => Ok(()),
        (State::Bidding, Action::PickWinner { lot_id }) => {
            a.winner_lot = Some(lot_id);
            a.state = State::Performing;
            Ok(())
        }
        (State::Bidding, Action::CancelAuction) => {
            a.state = State::Done { winner: None };
            Ok(())
        }

        (State::Performing, Action::Ready) => {
            a.state = State::Voting { started_at: now };
            Ok(())
        }
        (State::Performing, Action::ReturnLot { is_winner: true }) => {
            a.state = State::Done {
                winner: Some(Outcome::Cancel),
            };
            Ok(())
        }
        (
            State::Performing,
            Action::ReturnEntry {
                is_winner_lot: true,
            },
        ) => Ok(()),

        // Voting (winner lot only): record a non-duplicate, threshold-meeting vote.
        // Order per spec §Таблица переходов: dedup `(lot_id, voter)` before weight.
        (State::Voting { .. }, Action::Vote(v)) => {
            if a.votes.iter().any(|e| e.voter == v.voter) {
                return Err(StepError::DuplicateVoter);
            }
            if v.weight < MIN_VOTE_WEIGHT {
                return Err(StepError::WeightBelowThreshold);
            }
            a.votes.push(v);
            Ok(())
        }

        _ => Err(StepError::InvalidTransition),
    }
}

/// Whether an entry / its lot is unknown, live, or returned — the two-stage
/// prefix of the three-stage resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known {
    Unknown,
    Live,
    Returned,
}

/// Resolution of one escrow's claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Settle,
    Cancel,
    /// No verdict yet (a paid pull would refuse without charge).
    NoVerdict,
}

/// The three-stage resolution (auction spec §Трёхступенчатое разрешение), keyed on
/// one contribution: a returned entry cancels (stage 1); else a returned lot
/// cancels (stage 2); else the outcome is by the auction state and whether this
/// lot is the recipient-picked winner (stage 3). An unknown entry is resolved only
/// by stage 3 — never the winner, so `Cancel` in a terminal/loser state.
pub fn resolve(entry: Known, lot: Known, is_winner: bool, state: &State) -> Resolution {
    if entry == Known::Returned {
        return Resolution::Cancel;
    }
    if lot == Known::Returned {
        return Resolution::Cancel;
    }
    match state {
        State::Done { winner } => {
            if is_winner {
                match winner {
                    Some(Outcome::Settle) => Resolution::Settle,
                    // Winner-lot cancelled, or no winner at all.
                    Some(Outcome::Cancel) | None => Resolution::Cancel,
                }
            } else {
                Resolution::Cancel
            }
        }
        State::Performing | State::Voting { .. } => {
            if is_winner {
                Resolution::NoVerdict
            } else {
                Resolution::Cancel
            }
        }
        // No winner picked yet.
        State::Bidding => Resolution::NoVerdict,
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic, not the hot path
mod tests {
    use super::*;

    const CREATED: u64 = 1_000;
    const DUR: u64 = 600;
    const PW: u64 = 300;
    const VP: u64 = 120;

    fn auction(state: State) -> Auction {
        Auction {
            state,
            created_at: CREATED,
            duration: DUR,
            perform_window: PW,
            voting_period: VP,
            winner_lot: None,
            votes: Vec::new(),
        }
    }

    /// `State::admits` gates the boundary; `apply_action` gates the update. The
    /// asymmetry between them is deliberate (admission filters, refusal decides),
    /// so this pins the direction that actually protects us: **whatever `admits`
    /// refuses, `apply_action` must refuse too — for every parameterisation of
    /// the action and at every point in the clock.** A gap there is a doomed call
    /// admitted, executed replicated and billed to the canister.
    ///
    /// Enumerated, not sampled: 4 states × 8 kinds, each kind expanded to every
    /// concrete `Action`, each tried inside the bidding window and past it.
    #[test]
    fn whatever_admits_refuses_apply_action_refuses_at_every_clock() {
        use ActionKind as K;
        let states = [
            State::Bidding,
            State::Performing,
            State::Voting {
                started_at: CREATED,
            },
            State::Done { winner: None },
            State::Done {
                winner: Some(Outcome::Settle),
            },
        ];
        // Every kind, expanded to every concrete action it can become.
        let expansions: [(ActionKind, Vec<Action>); 8] = [
            (K::RegisterEntry, vec![Action::RegisterEntry]),
            (K::AcceptLot, vec![Action::AcceptLot]),
            (
                K::ReturnLot,
                vec![
                    Action::ReturnLot { is_winner: false },
                    Action::ReturnLot { is_winner: true },
                ],
            ),
            (
                K::ReturnEntry,
                vec![
                    Action::ReturnEntry {
                        is_winner_lot: false,
                    },
                    Action::ReturnEntry {
                        is_winner_lot: true,
                    },
                ],
            ),
            (K::PickWinner, vec![Action::PickWinner { lot_id: [7; 32] }]),
            (K::CancelAuction, vec![Action::CancelAuction]),
            (K::Ready, vec![Action::Ready]),
            (K::Vote, vec![Action::Vote(vote(1, MIN_VOTE_WEIGHT, true))]),
        ];
        // Inside the bidding window, and after it closed — `open` flips between.
        let clocks = [CREATED, CREATED + DUR + PW + VP + 1];

        for s in states {
            for (kind, actions) in &expansions {
                for a in actions {
                    for now in clocks {
                        let mut auc = auction(s.clone());
                        let applied = step(&mut auc, a.clone(), now);
                        if !s.admits(*kind) {
                            assert_eq!(
                                applied,
                                Err(StepError::InvalidTransition),
                                "admits() refused {kind:?} in {s:?}, but apply_action \
                                 accepted {a:?} at now={now}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The other direction, stated as coverage rather than equality: every kind
    /// `admits` allows must be genuinely reachable somewhere, or the boundary is
    /// merely permissive and proves nothing. Catches an `admits` that drifted
    /// into `true` for a transition the machine no longer has.
    #[test]
    fn every_admitted_kind_is_reachable_in_that_state() {
        use ActionKind as K;
        let cases = [
            (State::Bidding, K::RegisterEntry, Action::RegisterEntry),
            (State::Bidding, K::AcceptLot, Action::AcceptLot),
            (
                State::Bidding,
                K::ReturnLot,
                Action::ReturnLot { is_winner: false },
            ),
            (
                State::Bidding,
                K::ReturnEntry,
                Action::ReturnEntry {
                    is_winner_lot: false,
                },
            ),
            (
                State::Bidding,
                K::PickWinner,
                Action::PickWinner { lot_id: [7; 32] },
            ),
            (State::Bidding, K::CancelAuction, Action::CancelAuction),
            (State::Performing, K::Ready, Action::Ready),
            (
                State::Performing,
                K::ReturnLot,
                Action::ReturnLot { is_winner: true },
            ),
            (
                State::Performing,
                K::ReturnEntry,
                Action::ReturnEntry {
                    is_winner_lot: true,
                },
            ),
            (
                State::Voting {
                    started_at: CREATED,
                },
                K::Vote,
                Action::Vote(vote(1, MIN_VOTE_WEIGHT, true)),
            ),
        ];
        for (s, kind, a) in cases {
            assert!(s.admits(kind), "{kind:?} must be admitted in {s:?}");
            let mut auc = auction(s.clone());
            assert_eq!(
                step(&mut auc, a.clone(), CREATED),
                Ok(()),
                "{a:?} must be applicable in {s:?} — otherwise admits() is vacuous"
            );
        }
    }

    fn vote(voter: u8, weight: u128, done: bool) -> Vote {
        Vote {
            voter: [voter; 32],
            weight,
            done,
        }
    }

    fn bidding_end() -> u64 {
        CREATED + DUR
    }

    #[test]
    fn registration_freezes_at_t_but_state_stays_bidding() {
        // Before T: register/accept allowed.
        let mut a = auction(State::Bidding);
        assert_eq!(step(&mut a, Action::AcceptLot, bidding_end() - 1), Ok(()));
        // At T: register rejected (frozen), state stays Bidding (no auto-transition).
        let mut b = auction(State::Bidding);
        assert_eq!(
            step(&mut b, Action::RegisterEntry, bidding_end()),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(b.state, State::Bidding);
    }

    #[test]
    fn cancel_from_bidding_is_no_winner() {
        let mut a = auction(State::Bidding);
        assert_eq!(step(&mut a, Action::CancelAuction, 0), Ok(()));
        assert_eq!(a.state, State::Done { winner: None });
    }

    #[test]
    fn pick_winner_opens_performing_before_or_after_t() {
        // Pick during the window → Performing, winner_lot fixed.
        let mut a = auction(State::Bidding);
        assert_eq!(
            step(&mut a, Action::PickWinner { lot_id: [7; 32] }, 1),
            Ok(())
        );
        assert_eq!(a.state, State::Performing);
        assert_eq!(a.winner_lot, Some([7; 32]));
        // Pick after T still works (registration frozen, but picking is open).
        let mut b = auction(State::Bidding);
        assert_eq!(
            step(
                &mut b,
                Action::PickWinner { lot_id: [7; 32] },
                bidding_end() + 10
            ),
            Ok(())
        );
        assert_eq!(b.state, State::Performing);
        // Pick is not valid once already Performing.
        assert_eq!(
            step(&mut a, Action::PickWinner { lot_id: [8; 32] }, 2),
            Err(StepError::InvalidTransition)
        );
    }

    #[test]
    fn performing_times_out_to_cancel() {
        let mut a = auction(State::Performing);
        let end = CREATED + DUR + PW;
        // One second before → ready still works.
        let mut early = auction(State::Performing);
        assert_eq!(step(&mut early, Action::Ready, end - 1), Ok(()));
        assert_eq!(
            early.state,
            State::Voting {
                started_at: end - 1
            }
        );
        // At the boundary → Done{Cancel}, ready rejected.
        assert_eq!(
            step(&mut a, Action::Ready, end),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            a.state,
            State::Done {
                winner: Some(Outcome::Cancel)
            }
        );
    }

    #[test]
    fn winner_return_in_performing_cancels_the_auction() {
        let mut a = auction(State::Performing);
        assert_eq!(
            step(
                &mut a,
                Action::ReturnLot { is_winner: true },
                CREATED + DUR + 1
            ),
            Ok(())
        );
        assert_eq!(
            a.state,
            State::Done {
                winner: Some(Outcome::Cancel)
            }
        );
        // A loser lot cannot be return_lot'd in Performing (auto-cancelled).
        let mut b = auction(State::Performing);
        assert_eq!(
            step(
                &mut b,
                Action::ReturnLot { is_winner: false },
                CREATED + DUR + 1
            ),
            Err(StepError::InvalidTransition)
        );
    }

    #[test]
    fn voting_tally_finalizes_by_time() {
        let mut a = auction(State::Voting { started_at: 0 });
        a.votes = vec![vote(1, 300_000, true), vote(2, 100_000, false)];
        assert_eq!(step(&mut a, Action::Tick, VP), Ok(()));
        assert_eq!(
            a.state,
            State::Done {
                winner: Some(Outcome::Settle)
            }
        );
    }

    #[test]
    fn vote_only_in_voting_with_threshold_and_dedup() {
        let mut a = auction(State::Voting { started_at: 0 });
        assert_eq!(
            step(&mut a, Action::Vote(vote(1, MIN_VOTE_WEIGHT - 1, true)), 1),
            Err(StepError::WeightBelowThreshold)
        );
        assert_eq!(
            step(&mut a, Action::Vote(vote(1, 200_000, true)), 1),
            Ok(())
        );
        assert_eq!(
            step(&mut a, Action::Vote(vote(1, 200_000, false)), 1),
            Err(StepError::DuplicateVoter)
        );
        // Both a duplicate AND below threshold → dedup wins (order: dedup→weight).
        assert_eq!(
            step(&mut a, Action::Vote(vote(1, MIN_VOTE_WEIGHT - 1, false)), 1),
            Err(StepError::DuplicateVoter)
        );
        // Voting from Bidding is invalid.
        let mut b = auction(State::Bidding);
        assert_eq!(
            step(&mut b, Action::Vote(vote(1, 200_000, true)), 1),
            Err(StepError::InvalidTransition)
        );
    }

    #[test]
    fn done_is_absorbing() {
        let mut a = auction(State::Done {
            winner: Some(Outcome::Settle),
        });
        for act in [
            Action::Ready,
            Action::AcceptLot,
            Action::CancelAuction,
            Action::PickWinner { lot_id: [1; 32] },
            Action::Vote(vote(1, 200_000, true)),
        ] {
            assert_eq!(step(&mut a, act, 1), Err(StepError::InvalidTransition));
        }
    }

    #[test]
    fn overflow_leaves_state_untouched() {
        let mut a = Auction {
            created_at: u64::MAX,
            duration: 1,
            ..auction(State::Bidding)
        };
        assert_eq!(step(&mut a, Action::AcceptLot, 0), Err(StepError::Overflow));
        assert_eq!(a.state, State::Bidding);
    }

    #[test]
    fn resolve_stage_one_and_two_are_cancel() {
        let done = State::Done {
            winner: Some(Outcome::Settle),
        };
        assert_eq!(
            resolve(Known::Returned, Known::Live, true, &done),
            Resolution::Cancel
        );
        assert_eq!(
            resolve(Known::Live, Known::Returned, true, &done),
            Resolution::Cancel
        );
    }

    #[test]
    fn resolve_stage_three_by_state_and_winner() {
        let settle = State::Done {
            winner: Some(Outcome::Settle),
        };
        assert_eq!(
            resolve(Known::Live, Known::Live, true, &settle),
            Resolution::Settle
        );
        assert_eq!(
            resolve(Known::Live, Known::Live, false, &settle),
            Resolution::Cancel
        );
        let none = State::Done { winner: None };
        assert_eq!(
            resolve(Known::Live, Known::Live, false, &none),
            Resolution::Cancel
        );
        assert_eq!(
            resolve(Known::Live, Known::Live, true, &State::Performing),
            Resolution::NoVerdict
        );
        assert_eq!(
            resolve(Known::Live, Known::Live, false, &State::Performing),
            Resolution::Cancel
        );
        // Bidding: no verdict for anyone (winner not picked yet).
        assert_eq!(
            resolve(Known::Live, Known::Live, false, &State::Bidding),
            Resolution::NoVerdict
        );
        // Unknown entry (never the winner) in a terminal state → Cancel (stage 3).
        assert_eq!(
            resolve(Known::Unknown, Known::Unknown, false, &settle),
            Resolution::Cancel
        );
    }

    #[test]
    fn live_states_reject_registry_and_stray_actions() {
        // Beyond `done_is_absorbing`: in Performing/Voting the bidding-only
        // bookkeeping actions all fall through to InvalidTransition, leaving the
        // state untouched (the transition table's `✗` cells for live states).
        for state in [State::Performing, State::Voting { started_at: 0 }] {
            for act in [
                Action::RegisterEntry,
                Action::AcceptLot,
                Action::ReturnLot { is_winner: false },
                Action::CancelAuction,
                Action::PickWinner { lot_id: [1; 32] },
            ] {
                let mut a = auction(state.clone());
                assert_eq!(step(&mut a, act, 1), Err(StepError::InvalidTransition));
                assert_eq!(a.state, state);
            }
        }
        // `ready` is valid only from Performing → rejected in Bidding and Voting.
        let mut b = auction(State::Bidding);
        assert_eq!(
            step(&mut b, Action::Ready, 1),
            Err(StepError::InvalidTransition)
        );
        let mut v = auction(State::Voting { started_at: 0 });
        assert_eq!(
            step(&mut v, Action::Ready, 1),
            Err(StepError::InvalidTransition)
        );
        // `vote` is valid only from Voting → rejected in Performing.
        let mut p = auction(State::Performing);
        assert_eq!(
            step(&mut p, Action::Vote(vote(1, 200_000, true)), 1),
            Err(StepError::InvalidTransition)
        );
        // `return_entry` on a non-winner lot in Performing is rejected (only the
        // recipient-picked winner lot may be touched there).
        let mut q = auction(State::Performing);
        assert_eq!(
            step(
                &mut q,
                Action::ReturnEntry {
                    is_winner_lot: false
                },
                1
            ),
            Err(StepError::InvalidTransition)
        );
    }

    #[test]
    fn voting_tally_overflow_is_reported() {
        // `advance` in Voting computes `started_at + voting_period`; an
        // unrepresentable instant is `Overflow`, not a panic, and the state holds.
        let mut a = Auction {
            state: State::Voting {
                started_at: u64::MAX,
            },
            voting_period: 1,
            ..auction(State::Bidding)
        };
        assert_eq!(step(&mut a, Action::Tick, 0), Err(StepError::Overflow));
        assert_eq!(
            a.state,
            State::Voting {
                started_at: u64::MAX
            }
        );
    }

    #[test]
    fn performing_advance_overflow_is_reported() {
        // `advance` in Performing needs `created_at + duration + perform_window`;
        // overflow → `Overflow`, state untouched.
        let mut a = Auction {
            state: State::Performing,
            created_at: u64::MAX,
            duration: 1,
            ..auction(State::Bidding)
        };
        assert_eq!(step(&mut a, Action::Tick, 0), Err(StepError::Overflow));
        assert_eq!(a.state, State::Performing);
    }
}
