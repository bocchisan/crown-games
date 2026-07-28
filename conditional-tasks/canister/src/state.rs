//! Canister state + orchestration (in-memory). A new version is a fresh canister
//! (harness §7 bars state migration), so heap state is correct — nothing to
//! survive an upgrade. The update methods are thin `ic_cdk` wrappers over these
//! pure operations, which are host-testable.

use crate::validate::Profile;
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

/// A recipient profile plus its strictly-increasing counter.
#[derive(Clone, Copy)]
struct StoredProfile {
    profile: Profile,
    counter: u64,
}

thread_local! {
    static TASKS: RefCell<BTreeMap<[u8; 32], Stored>> = const { RefCell::new(BTreeMap::new()) };
    static PROFILES: RefCell<BTreeMap<[u8; 32], StoredProfile>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// State-level errors of an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    AlreadyExists,
    NotFound,
    NotRecipient,
    StaleCounter,
    VoteCapReached,
    ProfileCapReached,
    Step(StepError),
}

/// The lazy default profile (harness §Профиль): enabled, `min_gross = floor`,
/// no reputation gate, counter 0.
pub fn default_profile(floor: u64) -> Profile {
    Profile {
        enabled: true,
        min_gross: floor,
        min_reputation: 0,
    }
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

/// Whether a profile write would be admitted (read-only): the counter strictly
/// increases for an existing recipient, and the table has room for a new one.
/// The boundary (`inspect_message`) uses it to drop a doomed `set_profile` for
/// free; `set_profile` re-checks it before writing.
pub fn profile_admits(recipient: &[u8; 32], counter: u64, max: usize) -> Result<(), StateError> {
    PROFILES.with_borrow(|p| match p.get(recipient) {
        Some(existing) if counter <= existing.counter => Err(StateError::StaleCounter),
        Some(_) => Ok(()),
        None if p.len() >= max => Err(StateError::ProfileCapReached),
        None => Ok(()),
    })
}

/// Set a recipient's profile — the counter must strictly increase. Capped at
/// `max` distinct recipients: `set_profile` is the one write not gated by a
/// birth proof (any freshly-signed key can call it), so an unbounded `PROFILES`
/// would let anyone inflate heap state for free. An *existing* recipient updates
/// in place (no net growth); a *new* recipient is refused once the table is full
/// (non-negativity invariant #7, cost.md §6 — same shape as the per-area `V_MAX`
/// vote cap).
pub fn set_profile(
    recipient: [u8; 32],
    profile: Profile,
    counter: u64,
    max: usize,
) -> Result<(), StateError> {
    profile_admits(&recipient, counter, max)?;
    PROFILES.with_borrow_mut(|p| {
        p.insert(recipient, StoredProfile { profile, counter });
    });
    Ok(())
}

/// The effective profile plus its counter (0 if the recipient has none set).
pub fn profile_and_counter(recipient: &[u8; 32], floor: u64) -> (Profile, u64) {
    PROFILES.with_borrow(|p| {
        p.get(recipient)
            .map(|sp| (sp.profile, sp.counter))
            .unwrap_or_else(|| (default_profile(floor), 0))
    })
}

/// The effective profile for a recipient (the default if unset).
pub fn profile(recipient: &[u8; 32], floor: u64) -> Profile {
    PROFILES.with_borrow(|p| {
        p.get(recipient)
            .map(|sp| sp.profile)
            .unwrap_or_else(|| default_profile(floor))
    })
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
        PROFILES.with_borrow_mut(BTreeMap::clear);
    }

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

    #[test]
    fn profile_counter_must_increase() {
        reset();
        let r = [5u8; 32];
        let floor = 1_860_000;
        // Default until set.
        assert_eq!(profile(&r, floor), default_profile(floor));

        let p = Profile {
            enabled: false,
            min_gross: floor + 1,
            min_reputation: 7,
        };
        assert_eq!(set_profile(r, p, 1, 500), Ok(()));
        assert_eq!(profile(&r, floor), p);
        // Equal or lower counter is stale.
        assert_eq!(set_profile(r, p, 1, 500), Err(StateError::StaleCounter));
        assert_eq!(set_profile(r, p, 0, 500), Err(StateError::StaleCounter));
        // A higher counter updates.
        let p2 = Profile { enabled: true, ..p };
        assert_eq!(set_profile(r, p2, 2, 500), Ok(()));
        assert_eq!(profile(&r, floor), p2);
    }

    #[test]
    fn profiles_are_capped_but_existing_recipients_still_update() {
        reset();
        let p = default_profile(1_860_000);
        // Fill the table to a cap of 2 with two distinct recipients.
        assert_eq!(set_profile([1u8; 32], p, 1, 2), Ok(()));
        assert_eq!(set_profile([2u8; 32], p, 1, 2), Ok(()));
        // A third, new recipient is refused — no free unbounded growth.
        assert_eq!(
            set_profile([3u8; 32], p, 1, 2),
            Err(StateError::ProfileCapReached)
        );
        // But an already-stored recipient may still update in place (no growth).
        assert_eq!(set_profile([1u8; 32], p, 2, 2), Ok(()));
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
