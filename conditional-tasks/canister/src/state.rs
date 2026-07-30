//! Canister state + orchestration (in-memory). A new version is a fresh canister
//! (harness §7 bars state migration), so heap state is correct — nothing to
//! survive an upgrade. The update methods are thin `ic_cdk` wrappers over these
//! pure operations, which are host-testable.

use conditional_tasks_logic::{step, Action, Outcome, State, StepError, Task, Vote};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// A materialized task: the logic task, the recipient (for authorization), and
/// the text hash (only the hash — the task text never lives in the canister).
#[derive(Clone)]
struct Stored {
    task: Task,
    recipient: [u8; 32],
    text_hash: [u8; 32],
}

// The verdict signature store and its claim-before-await discipline live in
// `crown_games_common::signing` — non-negativity invariant #5, one mechanism
// for every game rather than three byte-identical copies (`P7.6`).
pub use crown_games_common::signing::SignedVerdict;

// There is no recipient-profile table. Acceptance terms (a minimum, a "not
// accepting") are a display filter, and the canister is the one place where the
// filter can no longer help: `register_task` needs a birth proof, so by the time
// it could refuse, the donor has already funded the escrow and paid for the
// birth ingest and the root push. Refusing there costs the donor three paid
// steps and protects nobody — an unwanted task is declined, or simply ignored
// until `refund()` returns the money at the deadline. Terms belong in front of
// the escrow, i.e. in the client. Removing the table also removes the one write
// with no escrow behind it, so `00 §11` ("ни одного хранимого байта без
// реального эскроу") now holds without exception (`P7.14`).

thread_local! {
    static TASKS: RefCell<BTreeMap<[u8; 32], Stored>> = const { RefCell::new(BTreeMap::new()) };
}

/// State-level errors of an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    AlreadyExists,
    NotFound,
    NotRecipient,
    VoteCapReached,
    Step(StepError),
}

/// Materialize a task. Idempotent by `task_id` — a duplicate is rejected (a
/// birth proof for an already-known task writes nothing).
pub fn materialize(
    task_id: [u8; 32],
    task: Task,
    recipient: [u8; 32],
    text_hash: [u8; 32],
) -> Result<(), StateError> {
    TASKS.with_borrow_mut(|t| {
        if t.contains_key(&task_id) {
            return Err(StateError::AlreadyExists);
        }
        t.insert(
            task_id,
            Stored {
                task,
                recipient,
                text_hash,
            },
        );
        Ok(())
    })
}

/// Apply a recipient action (`accept`/`decline`/`ready`): the signer must be the
/// task's recipient, then advance time + act + persist. Returns the new state.
pub fn recipient_action(
    task_id: &[u8; 32],
    signer: &[u8; 32],
    action: Action,
    now: i64,
) -> Result<State, StateError> {
    TASKS.with_borrow_mut(|t| {
        let s = t.get_mut(task_id).ok_or(StateError::NotFound)?;
        if s.recipient != *signer {
            return Err(StateError::NotRecipient);
        }
        step(&mut s.task, action, now).map_err(StateError::Step)?;
        Ok(s.task.state)
    })
}

/// Time-free boundary pre-check for a recipient action (harness §6), the twin of
/// [`vote_admits`]: the cheap committed-state reasons the action is doomed —
/// unknown task, wrong signer, or a stored state whose transition table does not
/// admit it.
///
/// Sound on the time-free boundary for the same reason `vote_admits` is: the only
/// move time can make is into `Decided`, which admits nothing, so an action the
/// stored state refuses is refused in every state time could have produced
/// (`conditional_tasks_logic::State::admits`, pinned to `apply_action` by an
/// exhaustive test). A strict subset of `recipient_action`'s rejections, which
/// stays the authoritative gate.
///
/// Without this the boundary admitted every action from the right signer and let
/// the update reject it — so a recipient (or anyone replaying their signed
/// message, since the extras are unsigned) could repeat `accept` forever and have
/// each copy executed, replicated, at the canister's expense.
pub fn action_admits(
    task_id: &[u8; 32],
    signer: &[u8; 32],
    action: &Action,
) -> Result<(), StateError> {
    TASKS.with_borrow(|t| {
        let s = t.get(task_id).ok_or(StateError::NotFound)?;
        if s.recipient != *signer {
            return Err(StateError::NotRecipient);
        }
        if !s.task.state.admits(action) {
            return Err(StateError::Step(StepError::InvalidTransition));
        }
        Ok(())
    })
}

/// The recipient a materialized task was created for (for weight-proof keying).
pub fn task_recipient(task_id: &[u8; 32]) -> Option<[u8; 32]> {
    TASKS.with_borrow(|t| t.get(task_id).map(|s| s.recipient))
}

/// Time-free boundary pre-check for a vote (harness §6): the cheap committed-state
/// reasons a vote is doomed — unknown task, over cap, duplicate voter, or a stored
/// state that is not `Voting`. Run in `admit_vote` *before* the weight proof so a
/// replayed/valid-proof-but-doomed vote dies at the boundary without a BLS pairing,
/// instead of re-verifying on the replicated path. A strict subset of `add_vote`'s
/// rejections (which stays the authoritative gate). Stored `Voting` suffices: it is
/// only ever left for `Decided` by time, never entered, so an effective `Voting`
/// implies a stored one.
pub fn vote_admits(task_id: &[u8; 32], voter: &[u8; 32], v_max: usize) -> Result<(), StateError> {
    TASKS.with_borrow(|t| {
        let s = t.get(task_id).ok_or(StateError::NotFound)?;
        if s.task.votes.len() >= v_max {
            return Err(StateError::VoteCapReached);
        }
        if s.task.votes.iter().any(|e| e.voter == *voter) {
            return Err(StateError::Step(StepError::DuplicateVoter));
        }
        if !matches!(s.task.state, State::Voting { .. }) {
            return Err(StateError::Step(StepError::InvalidTransition));
        }
        Ok(())
    })
}

/// Record a weight-proven vote: advance time, then act. Capped at `v_max` per
/// task (invariant #7). The `step` still enforces `Voting` state, the weight
/// threshold, and `(task_id, voter)` dedup.
pub fn add_vote(
    task_id: &[u8; 32],
    vote: Vote,
    now: i64,
    v_max: usize,
) -> Result<State, StateError> {
    TASKS.with_borrow_mut(|t| {
        let s = t.get_mut(task_id).ok_or(StateError::NotFound)?;
        if s.task.votes.len() >= v_max {
            return Err(StateError::VoteCapReached);
        }
        step(&mut s.task, Action::Vote(vote), now).map_err(StateError::Step)?;
        Ok(s.task.state)
    })
}

/// The materialized task's state (with accrued time transitions applied at `now`
/// via a `Tick`), or `None` if unknown. A pure read — no side effect on failure
/// beyond the persisted tick.
pub fn task_state(task_id: &[u8; 32], now: i64) -> Option<State> {
    TASKS.with_borrow_mut(|t| {
        let s = t.get_mut(task_id)?;
        let _ = step(&mut s.task, Action::Tick, now); // apply accrued transitions
        Some(s.task.state)
    })
}

/// The terminal outcome of a task, or `None` if not yet `Decided`.
pub fn verdict(task_id: &[u8; 32], now: i64) -> Option<Outcome> {
    match task_state(task_id, now)? {
        State::Decided { outcome } => Some(outcome),
        _ => None,
    }
}

pub fn is_materialized(task_id: &[u8; 32]) -> bool {
    TASKS.with_borrow(|t| t.contains_key(task_id))
}

/// The stored text hash of a task (only the hash is kept — never the text).
pub fn text_hash(task_id: &[u8; 32]) -> Option<[u8; 32]> {
    TASKS.with_borrow(|t| t.get(task_id).map(|s| s.text_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: i64 = 1_000_000;
    const VP: i64 = 120;

    fn fresh_task() -> Task {
        Task {
            state: State::Created,
            votes: Vec::new(),
            deadline: D,
            voting_period: VP,
        }
    }

    fn reset() {
        TASKS.with_borrow_mut(BTreeMap::clear);
        crown_games_common::signing::reset_for_test();
    }

    // The signature store's own behaviour — repeat served free, one claim at a
    // time, an aborted signing left retriable — is tested once, in
    // `crown_games_common::signing`. Re-testing it per game re-tested one
    // mechanism three times and told us nothing about this game (`P7.6`).

    #[test]
    fn materialize_is_idempotent() {
        reset();
        let id = [1u8; 32];
        assert_eq!(materialize(id, fresh_task(), [2; 32], [3; 32]), Ok(()));
        assert!(is_materialized(&id));
        assert_eq!(text_hash(&id), Some([3u8; 32]));
        // A second birth proof for the same task writes nothing.
        assert_eq!(
            materialize(id, fresh_task(), [2; 32], [3; 32]),
            Err(StateError::AlreadyExists)
        );
    }

    #[test]
    fn only_the_recipient_may_act() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];
        materialize(id, fresh_task(), recipient, [3; 32]).unwrap();

        // A stranger cannot accept.
        assert_eq!(
            recipient_action(&id, &[8u8; 32], Action::Accept, 0),
            Err(StateError::NotRecipient)
        );
        // The recipient can, and the state advances.
        assert_eq!(
            recipient_action(&id, &recipient, Action::Accept, 0),
            Ok(State::Accepted)
        );
        // An unknown task is NotFound.
        assert_eq!(
            recipient_action(&[7u8; 32], &recipient, Action::Accept, 0),
            Err(StateError::NotFound)
        );
    }

    #[test]
    fn a_rejected_action_surfaces_the_step_error() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];
        materialize(id, fresh_task(), recipient, [3; 32]).unwrap();
        recipient_action(&id, &recipient, Action::Accept, 0).unwrap();
        // Accept again → invalid transition (state stays Accepted).
        assert_eq!(
            recipient_action(&id, &recipient, Action::Accept, 0),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        assert_eq!(task_state(&id, 0), Some(State::Accepted));
    }

    #[test]
    fn verdict_is_none_until_decided_then_the_outcome() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];
        materialize(id, fresh_task(), recipient, [3; 32]).unwrap();
        assert_eq!(verdict(&id, 0), None);
        // Decline → Cancel; verdict now present.
        recipient_action(&id, &recipient, Action::Decline, 0).unwrap();
        assert_eq!(verdict(&id, 0), Some(Outcome::Cancel));
    }

    #[test]
    fn a_lazy_tick_finalizes_a_stuck_voting_task() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];
        let mut task = fresh_task();
        task.state = State::Voting { started_at: 0 };
        task.votes = vec![Vote {
            voter: [1; 32],
            weight: 200_000,
            done: true,
        }];
        materialize(id, task, recipient, [3; 32]).unwrap();
        // Reading past voting_end tallies the verdict without any action.
        let voting_end = D - conditional_tasks_logic::DEADLINE_MARGIN;
        assert_eq!(
            task_state(&id, voting_end),
            Some(State::Decided {
                outcome: Outcome::Settle
            })
        );
    }

    fn voting_task(id: [u8; 32], recipient: [u8; 32]) {
        let mut task = fresh_task();
        task.state = State::Voting { started_at: 0 };
        materialize(id, task, recipient, [3; 32]).unwrap();
    }

    fn vote(voter: u8, weight: u128, done: bool) -> Vote {
        Vote {
            voter: [voter; 32],
            weight,
            done,
        }
    }

    #[test]
    fn add_vote_records_dedups_and_caps() {
        reset();
        let id = [1u8; 32];
        voting_task(id, [9u8; 32]);
        assert_eq!(task_recipient(&id), Some([9u8; 32]));

        // A weight-proven vote is recorded.
        assert_eq!(
            add_vote(&id, vote(1, 200_000, true), 0, 500),
            Ok(State::Voting { started_at: 0 })
        );
        // Below the weight threshold → rejected by the step.
        assert_eq!(
            add_vote(&id, vote(2, 99_999, true), 0, 500),
            Err(StateError::Step(StepError::WeightBelowThreshold))
        );
        // Same voter again → duplicate.
        assert_eq!(
            add_vote(&id, vote(1, 200_000, false), 0, 500),
            Err(StateError::Step(StepError::DuplicateVoter))
        );
        // The V_MAX cap: with one vote in and cap 1, the next is capped.
        assert_eq!(
            add_vote(&id, vote(3, 200_000, true), 0, 1),
            Err(StateError::VoteCapReached)
        );
    }

    #[test]
    fn add_vote_requires_voting_state() {
        reset();
        let id = [1u8; 32];
        materialize(id, fresh_task(), [9u8; 32], [3; 32]).unwrap(); // Created
        assert_eq!(
            add_vote(&id, vote(1, 200_000, true), 0, 500),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        assert_eq!(
            add_vote(&[7u8; 32], vote(1, 200_000, true), 0, 500),
            Err(StateError::NotFound)
        );
    }

    /// The boundary must refuse a doomed recipient action, not leave it to the
    /// update. This is the check whose absence let one signed `accept` be
    /// replayed forever at the canister's expense.
    #[test]
    fn action_admits_refuses_what_the_state_will_refuse() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];

        // Unknown task → NotFound, before anything else.
        assert_eq!(
            action_admits(&id, &recipient, &Action::Accept),
            Err(StateError::NotFound)
        );

        materialize(id, fresh_task(), recipient, [3; 32]).unwrap();
        // A stranger is refused even for an action the state does admit.
        assert_eq!(
            action_admits(&id, &[8u8; 32], &Action::Accept),
            Err(StateError::NotRecipient)
        );
        // `Created` admits accept/decline, not ready.
        assert_eq!(action_admits(&id, &recipient, &Action::Accept), Ok(()));
        assert_eq!(action_admits(&id, &recipient, &Action::Decline), Ok(()));
        assert_eq!(
            action_admits(&id, &recipient, &Action::Ready),
            Err(StateError::Step(StepError::InvalidTransition))
        );

        // After accept, a *second* accept is doomed — and now dies here, at the
        // boundary, instead of being executed and refused by the update.
        recipient_action(&id, &recipient, Action::Accept, 0).unwrap();
        assert_eq!(
            action_admits(&id, &recipient, &Action::Accept),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        assert_eq!(action_admits(&id, &recipient, &Action::Ready), Ok(()));

        // Decided is absorbing: nothing is admitted, ever.
        recipient_action(&id, &recipient, Action::Decline, 0).unwrap();
        for a in [Action::Accept, Action::Decline, Action::Ready] {
            assert_eq!(
                action_admits(&id, &recipient, &a),
                Err(StateError::Step(StepError::InvalidTransition)),
                "{a:?} must be refused on a decided task"
            );
        }
    }

    /// Every rejection the boundary makes must be one the update would also
    /// make — otherwise a legitimate call is dropped for free and looks to the
    /// client like a refusal without a reason.
    #[test]
    fn action_admits_never_refuses_what_the_update_would_accept() {
        for (setup, action) in [
            (None, Action::Accept),
            (None, Action::Decline),
            (Some(Action::Accept), Action::Ready),
            (Some(Action::Accept), Action::Decline),
        ] {
            reset();
            let id = [1u8; 32];
            let recipient = [9u8; 32];
            materialize(id, fresh_task(), recipient, [3; 32]).unwrap();
            if let Some(pre) = setup {
                recipient_action(&id, &recipient, pre, 0).unwrap();
            }
            assert_eq!(
                action_admits(&id, &recipient, &action),
                Ok(()),
                "boundary refused {action:?}, which the update accepts"
            );
            assert!(
                recipient_action(&id, &recipient, action.clone(), 0).is_ok(),
                "update refused {action:?} the boundary admitted"
            );
        }
    }

    #[test]
    fn vote_admits_is_a_subset_of_add_vote_and_needs_no_weight_proof() {
        reset();
        let id = [1u8; 32];
        // Unknown task → NotFound; the boundary drops it before any BLS.
        assert_eq!(vote_admits(&id, &[1; 32], 500), Err(StateError::NotFound));
        // Materialized but Created (not Voting) → InvalidTransition.
        materialize(id, fresh_task(), [9u8; 32], [3; 32]).unwrap();
        assert_eq!(
            vote_admits(&id, &[1; 32], 500),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        // A Voting task with one recorded vote: a replay is DuplicateVoter, a fresh
        // voter is admitted, and the cap is checked first.
        reset();
        voting_task(id, [9u8; 32]);
        add_vote(&id, vote(1, 200_000, true), 0, 500).unwrap();
        assert_eq!(
            vote_admits(&id, &[1; 32], 500),
            Err(StateError::Step(StepError::DuplicateVoter))
        );
        assert_eq!(vote_admits(&id, &[2; 32], 500), Ok(()));
        assert_eq!(
            vote_admits(&id, &[2; 32], 1),
            Err(StateError::VoteCapReached)
        );
    }
}
