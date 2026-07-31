//! Auction state machine (auction spec §Состояния, §Таблица переходов,
//! §Трёхступенчатое разрешение).
//!
//! Two states, because the auction has exactly two moments: the bidding window,
//! and its close. At `T = created_at + duration` the window shuts and the
//! heaviest eligible lot wins — arithmetic, not anyone's choice. Nobody votes and
//! nobody picks, so there is no stage between the close and the outcome.
//!
//! Time is applied **before** the action (lazily), so a call that arrives after
//! `T` finds a closed auction rather than a window it can still act in. The close
//! is the only time transition, its instant is absolute, and all time arithmetic
//! is `checked` — an unrepresentable instant is `Overflow` and leaves the state
//! untouched.
//!
//! The machine does not hold lots, so it cannot compute the winner itself: the
//! canister passes `top`, its one pass over the eligible lots. It is a closure
//! because a call inside the window must not pay for a scan it will not use.

/// Auction state.
///
/// `Done { winner_lot: Some(lot) }` — that lot outbid every other eligible lot at
/// the close and settles; every other contribution cancels. `None` — nobody won:
/// the recipient cancelled, or no eligible lot stood when the window shut. Either
/// way `Done` is absorbing, so the winner is fixed the instant it is computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Bidding,
    Done { winner_lot: Option<[u8; 32]> },
}

/// Actions (auction spec §Таблица переходов). None carries a parameter the
/// machine reads: registration, acceptance and the two returns are the canister's
/// lot bookkeeping, gated here only by the window still being open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    RegisterEntry,
    AcceptLot,
    ReturnLot,
    ReturnEntry,
    CancelAuction,
}

/// Errors of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepError {
    InvalidTransition,
    Overflow,
}

/// The auction as a state machine: state + the immutable timing anchors
/// (`created_at` = the first confirmed entry's birth slot→time, `duration`
/// snapped from the `auction_id` preimage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auction {
    pub state: State,
    pub created_at: u64,
    pub duration: u64,
}

impl Auction {
    /// End of the bidding window (`T`): the auction closes here.
    fn bidding_end(&self) -> Result<u64, StepError> {
        self.created_at
            .checked_add(self.duration)
            .ok_or(StepError::Overflow)
    }
}

/// Apply the accrued close: at `now ≥ T` the window shuts and `top` names the
/// winner. Idempotent — `Done` is absorbing, so `top` is consulted exactly once
/// per auction, and never at all for an auction that ends by `cancel`.
///
/// The answer does not depend on *when* the first call after `T` arrives: every
/// action that could move a lot's standing needs `Bidding`, which `now ≥ T` has
/// already left, so the set `top` reads is frozen at `T`.
pub fn tick(
    a: &mut Auction,
    now: u64,
    top: impl FnOnce() -> Option<[u8; 32]>,
) -> Result<(), StepError> {
    if matches!(a.state, State::Bidding) && now >= a.bidding_end()? {
        a.state = State::Done { winner_lot: top() };
    }
    Ok(())
}

/// One step: the accrued close, then the action. A rejected action keeps the
/// closed state; a time-arithmetic overflow returns `Overflow` and leaves the
/// state untouched.
pub fn step(
    a: &mut Auction,
    action: Action,
    now: u64,
    top: impl FnOnce() -> Option<[u8; 32]>,
) -> Result<(), StepError> {
    tick(a, now, top)?;
    apply_action(a, action)
}

/// Apply an action to the (already advanced) state.
fn apply_action(a: &mut Auction, action: Action) -> Result<(), StepError> {
    match (&a.state, action) {
        // Absorbing: the winner is fixed, and no bookkeeping can move it.
        (State::Done { .. }, _) => Err(StepError::InvalidTransition),
        (State::Bidding, Action::CancelAuction) => {
            a.state = State::Done { winner_lot: None };
            Ok(())
        }
        // Lot bookkeeping the canister performs; the machine only gates the window.
        (
            State::Bidding,
            Action::RegisterEntry | Action::AcceptLot | Action::ReturnLot | Action::ReturnEntry,
        ) => Ok(()),
    }
}

impl State {
    /// Whether this state admits **any** action — the time-free, parameter-free
    /// half of `apply_action`'s verdict, for the boundary (`games-harness.md §6`).
    ///
    /// With the winner arithmetic there is exactly one live state and every action
    /// belongs to it, so the check no longer needs to know *which* action: the
    /// parameter is gone rather than ignored.
    ///
    /// Answered against the stored, un-advanced state, and that is the whole
    /// conservatism: `Bidding` leaves itself only for `Done`, which admits
    /// nothing, so no action ever becomes admissible later and a `false` here is
    /// doomed for every `now`. A `true` is a filter, never a verdict — the update
    /// still advances the clock (possibly straight into `Done`) and may refuse.
    pub fn admits(&self) -> bool {
        matches!(self, State::Bidding)
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
/// lot is the one that won the close (stage 3). An unknown entry is resolved only
/// by stage 3 — never the winner, so `Cancel` once closed.
pub fn resolve(entry: Known, lot: Known, is_winner: bool, state: &State) -> Resolution {
    if entry == Known::Returned {
        return Resolution::Cancel;
    }
    if lot == Known::Returned {
        return Resolution::Cancel;
    }
    match state {
        // The winner settles; everyone else — and everyone, when nobody won —
        // cancels. `is_winner` is `Done{winner_lot} == Some(this lot)`, so a
        // winnerless close cancels every contribution by construction.
        State::Done { .. } => {
            if is_winner {
                Resolution::Settle
            } else {
                Resolution::Cancel
            }
        }
        // Still bidding: the standing can still move, so nothing is decided.
        State::Bidding => Resolution::NoVerdict,
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic, not the hot path
mod tests {
    use super::*;

    const CREATED: u64 = 1_000;
    const DUR: u64 = 600;
    const TOP: [u8; 32] = [7; 32];

    fn auction(state: State) -> Auction {
        Auction {
            state,
            created_at: CREATED,
            duration: DUR,
        }
    }

    fn bidding_end() -> u64 {
        CREATED + DUR
    }

    /// The scan the canister supplies, standing in for its lot pass.
    fn top() -> Option<[u8; 32]> {
        Some(TOP)
    }

    const ACTIONS: [Action; 5] = [
        Action::RegisterEntry,
        Action::AcceptLot,
        Action::ReturnLot,
        Action::ReturnEntry,
        Action::CancelAuction,
    ];

    #[test]
    fn the_window_closes_at_t_and_the_top_lot_wins() {
        // One second before T the window is still open and registration lands.
        let mut a = auction(State::Bidding);
        assert_eq!(
            step(&mut a, Action::RegisterEntry, bidding_end() - 1, top),
            Ok(())
        );
        assert_eq!(a.state, State::Bidding);
        // At T it shuts, `top` names the winner, and the action is refused.
        assert_eq!(
            step(&mut a, Action::RegisterEntry, bidding_end(), top),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            a.state,
            State::Done {
                winner_lot: Some(TOP)
            }
        );
    }

    #[test]
    fn a_close_with_no_eligible_lot_has_no_winner() {
        let mut a = auction(State::Bidding);
        assert_eq!(tick(&mut a, bidding_end(), || None), Ok(()));
        assert_eq!(a.state, State::Done { winner_lot: None });
    }

    /// The winner is computed once and never recomputed — otherwise a later call
    /// with a different scan result could move money that is already decided.
    #[test]
    fn the_winner_is_fixed_at_the_close_and_never_recomputed() {
        let mut a = auction(State::Bidding);
        assert_eq!(tick(&mut a, bidding_end(), top), Ok(()));
        // A second tick, with a scan that would name someone else, changes nothing.
        assert_eq!(
            tick(&mut a, bidding_end() + 10_000, || Some([9; 32])),
            Ok(())
        );
        assert_eq!(
            a.state,
            State::Done {
                winner_lot: Some(TOP)
            }
        );
    }

    /// `top` is the canister's pass over its lots. Paying for it inside the window
    /// — on every register, accept and return — is the cost this laziness exists
    /// to avoid, so pin that it is not called until the window actually shuts.
    #[test]
    fn top_is_not_consulted_while_the_window_is_open() {
        let mut a = auction(State::Bidding);
        let mut consulted = false;
        assert_eq!(
            step(&mut a, Action::AcceptLot, CREATED, || {
                consulted = true;
                Some(TOP)
            }),
            Ok(())
        );
        assert!(!consulted, "the scan ran inside the open window");
    }

    #[test]
    fn cancel_from_bidding_is_no_winner() {
        let mut a = auction(State::Bidding);
        assert_eq!(step(&mut a, Action::CancelAuction, CREATED, top), Ok(()));
        assert_eq!(a.state, State::Done { winner_lot: None });
    }

    /// A cancel racing the close loses: time is applied first, so the auction is
    /// already `Done` with its winner and the cancel is refused. Without this a
    /// recipient could undo a close they did not like.
    #[test]
    fn cancel_after_t_cannot_undo_the_close() {
        let mut a = auction(State::Bidding);
        assert_eq!(
            step(&mut a, Action::CancelAuction, bidding_end(), top),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            a.state,
            State::Done {
                winner_lot: Some(TOP)
            }
        );
    }

    #[test]
    fn done_is_absorbing() {
        for winner_lot in [Some(TOP), None] {
            for act in ACTIONS {
                let mut a = auction(State::Done { winner_lot });
                assert_eq!(
                    step(&mut a, act, CREATED, top),
                    Err(StepError::InvalidTransition)
                );
                assert_eq!(a.state, State::Done { winner_lot });
            }
        }
    }

    /// `admits` gates the boundary; `apply_action` gates the update. The direction
    /// that protects us: **whatever `admits` refuses, the machine must refuse too
    /// — for every action and at every point in the clock.** A gap there is a
    /// doomed call admitted, executed replicated and billed to the canister.
    #[test]
    fn whatever_admits_refuses_step_refuses_at_every_clock() {
        let states = [
            State::Bidding,
            State::Done {
                winner_lot: Some(TOP),
            },
            State::Done { winner_lot: None },
        ];
        // Inside the bidding window, and past it — the close flips between.
        let clocks = [CREATED, bidding_end(), bidding_end() + 1];
        for s in states {
            for act in ACTIONS {
                for now in clocks {
                    let mut a = auction(s.clone());
                    let applied = step(&mut a, act, now, top);
                    if !s.admits() {
                        assert_eq!(
                            applied,
                            Err(StepError::InvalidTransition),
                            "admits() refused {s:?}, but step accepted {act:?} at now={now}"
                        );
                    }
                }
            }
        }
    }

    /// The other direction, as coverage: what `admits` allows must be genuinely
    /// reachable, or the boundary is merely permissive and proves nothing.
    #[test]
    fn every_action_is_reachable_while_bidding() {
        assert!(State::Bidding.admits());
        for act in ACTIONS {
            let mut a = auction(State::Bidding);
            assert_eq!(
                step(&mut a, act, CREATED, top),
                Ok(()),
                "{act:?} must be applicable while Bidding — otherwise admits() is vacuous"
            );
        }
    }

    #[test]
    fn overflow_leaves_state_untouched() {
        let mut a = Auction {
            created_at: u64::MAX,
            duration: 1,
            ..auction(State::Bidding)
        };
        assert_eq!(
            step(&mut a, Action::AcceptLot, 0, top),
            Err(StepError::Overflow)
        );
        assert_eq!(a.state, State::Bidding);
    }

    #[test]
    fn resolve_stage_one_and_two_are_cancel() {
        let done = State::Done {
            winner_lot: Some(TOP),
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

    /// Stages 1 and 2 outrank the state, and that ordering is the whole point of
    /// them being stages: a returned entry or a returned lot is **already**
    /// terminal — nothing un-returns, and neither can ever win the close — so its
    /// `Cancel` is available the moment it is returned, not at `T`.
    ///
    /// Without this the money of a lot the recipient rejected on day 1 of a 30-day
    /// auction sits locked behind a decision that was already made.
    #[test]
    fn a_returned_entry_or_lot_resolves_while_the_window_is_still_open() {
        assert_eq!(
            resolve(Known::Returned, Known::Live, false, &State::Bidding),
            Resolution::Cancel
        );
        assert_eq!(
            resolve(Known::Live, Known::Returned, false, &State::Bidding),
            Resolution::Cancel
        );
        // A live entry in a live lot is genuinely undecided — the standing moves.
        assert_eq!(
            resolve(Known::Live, Known::Live, false, &State::Bidding),
            Resolution::NoVerdict
        );
    }

    #[test]
    fn resolve_stage_three_by_state_and_winner() {
        let done = State::Done {
            winner_lot: Some(TOP),
        };
        assert_eq!(
            resolve(Known::Live, Known::Live, true, &done),
            Resolution::Settle
        );
        assert_eq!(
            resolve(Known::Live, Known::Live, false, &done),
            Resolution::Cancel
        );
        // Nobody won → nobody is the winner → everyone cancels.
        let none = State::Done { winner_lot: None };
        assert_eq!(
            resolve(Known::Live, Known::Live, false, &none),
            Resolution::Cancel
        );
        // Bidding: the standing can still move, so no verdict for anyone.
        assert_eq!(
            resolve(Known::Live, Known::Live, true, &State::Bidding),
            Resolution::NoVerdict
        );
        // Unknown entry (never the winner) once closed → Cancel (stage 3).
        assert_eq!(
            resolve(Known::Unknown, Known::Unknown, false, &done),
            Resolution::Cancel
        );
    }
}
