//! Canister state + orchestration (in-memory). A new version is a fresh canister
//! (harness §7 bars state migration), so heap state is correct — nothing to
//! survive an upgrade. Blind and registryless: one record **per collection**
//! keyed by `collection_id`; the canister never stores the individual `N`
//! contributions (their membership is derivation, proven on-chain by the shared
//! `resolver`). The update methods are thin `ic_cdk` wrappers over these pure,
//! host-testable operations.

use conditional_funding_logic::{step, Action, Collection, Outcome, State, StepError, Vote};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// A materialized collection: the logic machine plus the recipient (for
/// authorizing `ready`/`recipient_cancel`). Everything time-bound (`created_at`,
/// `duration`, `voting_period`, the verdict params) already lives in `Collection`.
#[derive(Clone)]
struct Stored {
    collection: Collection,
    recipient: [u8; 32],
}

thread_local! {
    static COLLECTIONS: RefCell<BTreeMap<[u8; 32], Stored>> =
        const { RefCell::new(BTreeMap::new()) };
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

/// Materialize a collection from its first funded contribution. Idempotent by
/// `collection_id` — a duplicate birth proof writes nothing.
pub fn materialize(
    collection_id: [u8; 32],
    collection: Collection,
    recipient: [u8; 32],
) -> Result<(), StateError> {
    COLLECTIONS.with_borrow_mut(|c| {
        if c.contains_key(&collection_id) {
            return Err(StateError::AlreadyExists);
        }
        c.insert(
            collection_id,
            Stored {
                collection,
                recipient,
            },
        );
        Ok(())
    })
}

/// Whether a collection has been materialized (a birth proof landed).
pub fn is_materialized(collection_id: &[u8; 32]) -> bool {
    COLLECTIONS.with_borrow(|c| c.contains_key(collection_id))
}

/// Apply a recipient action (`ready`/`recipient_cancel`): the signer must be the
/// collection's recipient, then advance time + act + persist. Returns the new
/// state. An unmaterialized collection is `NotFound` (harness: `ready`/`cancel`
/// never materialize).
pub fn recipient_action(
    collection_id: &[u8; 32],
    signer: &[u8; 32],
    action: Action,
    now: u64,
) -> Result<State, StateError> {
    COLLECTIONS.with_borrow_mut(|c| {
        let s = c.get_mut(collection_id).ok_or(StateError::NotFound)?;
        if s.recipient != *signer {
            return Err(StateError::NotRecipient);
        }
        step(&mut s.collection, action, now).map_err(StateError::Step)?;
        Ok(s.collection.state)
    })
}

/// The recipient a collection was materialized for (for weight-proof keying).
pub fn collection_recipient(collection_id: &[u8; 32]) -> Option<[u8; 32]> {
    COLLECTIONS.with_borrow(|c| c.get(collection_id).map(|s| s.recipient))
}

/// Time-free boundary pre-check for a vote (harness §6): the cheap committed-state
/// reasons a vote is doomed — unknown collection, over cap, duplicate voter, or a
/// stored state that is not `Voting`. Run in `admit_vote` *before* the weight
/// proof so a replayed/valid-proof-but-doomed vote dies at the boundary without a
/// BLS pairing, instead of re-verifying on the replicated path. A strict subset of
/// `add_vote`'s rejections (which stays the authoritative gate). Stored `Voting`
/// suffices: it is only ever left for `Decided` by time, never entered, so an
/// effective `Voting` implies a stored one.
pub fn vote_admits(
    collection_id: &[u8; 32],
    voter: &[u8; 32],
    v_max: usize,
) -> Result<(), StateError> {
    COLLECTIONS.with_borrow(|c| {
        let s = c.get(collection_id).ok_or(StateError::NotFound)?;
        if s.collection.votes.len() >= v_max {
            return Err(StateError::VoteCapReached);
        }
        if s.collection.votes.iter().any(|e| e.voter == *voter) {
            return Err(StateError::Step(StepError::DuplicateVoter));
        }
        if !matches!(s.collection.state, State::Voting { .. }) {
            return Err(StateError::Step(StepError::InvalidTransition));
        }
        Ok(())
    })
}

/// Record a weight-proven vote: advance time, then act. Capped at `v_max` per
/// collection (invariant #7). The `step` still enforces `Voting` state, the
/// weight threshold, and `(collection_id, voter)` dedup.
pub fn add_vote(
    collection_id: &[u8; 32],
    vote: Vote,
    now: u64,
    v_max: usize,
) -> Result<State, StateError> {
    COLLECTIONS.with_borrow_mut(|c| {
        let s = c.get_mut(collection_id).ok_or(StateError::NotFound)?;
        if s.collection.votes.len() >= v_max {
            return Err(StateError::VoteCapReached);
        }
        step(&mut s.collection, Action::Vote(vote), now).map_err(StateError::Step)?;
        Ok(s.collection.state)
    })
}

/// The materialized collection's state (with accrued time transitions applied at
/// `now` via a `Tick`), or `None` if unknown.
pub fn collection_state(collection_id: &[u8; 32], now: u64) -> Option<State> {
    COLLECTIONS.with_borrow_mut(|c| {
        let s = c.get_mut(collection_id)?;
        let _ = step(&mut s.collection, Action::Tick, now); // apply accrued transitions
        Some(s.collection.state)
    })
}

/// The terminal outcome of a collection, or `None` if not yet `Decided`.
pub fn verdict(collection_id: &[u8; 32], now: u64) -> Option<Outcome> {
    match collection_state(collection_id, now)? {
        State::Decided { outcome } => Some(outcome),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic, not the hot path
mod tests {
    use super::*;

    const CREATED: u64 = 1_000_000;
    const DUR: u64 = 600;
    const VP: u64 = 120;
    const Q: u128 = 150_000;
    const T: u16 = 5_000;

    fn fresh_collection() -> Collection {
        Collection {
            state: State::Funding,
            votes: Vec::new(),
            created_at: CREATED,
            duration: DUR,
            voting_period: VP,
            quorum_weight: Q,
            approval_threshold: T,
        }
    }

    fn reset() {
        COLLECTIONS.with_borrow_mut(BTreeMap::clear);
    }

    fn vote(voter: u8, weight: u128, done: bool) -> Vote {
        Vote {
            voter: [voter; 32],
            weight,
            done,
        }
    }

    #[test]
    fn materialize_is_idempotent() {
        reset();
        let id = [1u8; 32];
        assert_eq!(materialize(id, fresh_collection(), [2; 32]), Ok(()));
        assert!(COLLECTIONS.with_borrow(|c| c.contains_key(&id)));
        assert_eq!(collection_recipient(&id), Some([2u8; 32]));
        // A second birth proof for the same collection writes nothing.
        assert_eq!(
            materialize(id, fresh_collection(), [2; 32]),
            Err(StateError::AlreadyExists)
        );
    }

    #[test]
    fn only_the_recipient_may_act_and_unknown_is_not_found() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];
        materialize(id, fresh_collection(), recipient).unwrap();

        // A stranger cannot ready.
        assert_eq!(
            recipient_action(&id, &[8u8; 32], Action::Ready, CREATED + 1),
            Err(StateError::NotRecipient)
        );
        // The recipient can, opening Voting.
        assert_eq!(
            recipient_action(&id, &recipient, Action::Ready, CREATED + 1),
            Ok(State::Voting {
                started_at: CREATED + 1
            })
        );
        // An unmaterialized collection is NotFound (ready never materializes).
        assert_eq!(
            recipient_action(&[7u8; 32], &recipient, Action::Ready, CREATED + 1),
            Err(StateError::NotFound)
        );
    }

    #[test]
    fn recipient_cancel_refunds_and_verdict_surfaces() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];
        materialize(id, fresh_collection(), recipient).unwrap();
        assert_eq!(verdict(&id, CREATED), None);
        assert_eq!(
            recipient_action(&id, &recipient, Action::RecipientCancel, CREATED + 1),
            Ok(State::Decided {
                outcome: Outcome::Refund
            })
        );
        assert_eq!(verdict(&id, CREATED + 1), Some(Outcome::Refund));
    }

    #[test]
    fn add_vote_records_dedups_and_caps() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];
        let mut c = fresh_collection();
        c.state = State::Voting {
            started_at: CREATED,
        };
        materialize(id, c, recipient).unwrap();
        let now = CREATED + 1;

        assert_eq!(
            add_vote(&id, vote(1, 200_000, true), now, 500),
            Ok(State::Voting {
                started_at: CREATED
            })
        );
        // Below the weight threshold → rejected by the step.
        assert_eq!(
            add_vote(&id, vote(2, 99_999, true), now, 500),
            Err(StateError::Step(StepError::WeightBelowThreshold))
        );
        // Same voter again → duplicate.
        assert_eq!(
            add_vote(&id, vote(1, 200_000, false), now, 500),
            Err(StateError::Step(StepError::DuplicateVoter))
        );
        // The V_MAX cap: with one vote in and cap 1, the next is capped.
        assert_eq!(
            add_vote(&id, vote(3, 200_000, true), now, 1),
            Err(StateError::VoteCapReached)
        );
    }

    #[test]
    fn a_lazy_tick_finalizes_a_stuck_voting_collection() {
        reset();
        let id = [1u8; 32];
        let mut c = fresh_collection();
        c.state = State::Voting {
            started_at: CREATED,
        };
        c.votes = vec![vote(1, Q, true)]; // quorum-meeting all-yes
        materialize(id, c, [9u8; 32]).unwrap();
        // Reading past voting_end tallies the verdict without any action.
        assert_eq!(
            collection_state(&id, CREATED + VP),
            Some(State::Decided {
                outcome: Outcome::Settle
            })
        );
    }

    #[test]
    fn add_vote_requires_voting_state() {
        reset();
        let id = [1u8; 32];
        materialize(id, fresh_collection(), [9u8; 32]).unwrap(); // Funding
        assert_eq!(
            add_vote(&id, vote(1, 200_000, true), CREATED + 1, 500),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        assert_eq!(
            add_vote(&[7u8; 32], vote(1, 200_000, true), CREATED + 1, 500),
            Err(StateError::NotFound)
        );
    }

    #[test]
    fn vote_admits_is_a_subset_of_add_vote_and_needs_no_weight_proof() {
        reset();
        let id = [1u8; 32];
        // Unknown collection → NotFound; the boundary drops it before any BLS.
        assert_eq!(vote_admits(&id, &[1; 32], 500), Err(StateError::NotFound));
        // Materialized but Funding (not Voting) → InvalidTransition.
        materialize(id, fresh_collection(), [9u8; 32]).unwrap();
        assert_eq!(
            vote_admits(&id, &[1; 32], 500),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        // A Voting collection with one recorded vote: a replay is DuplicateVoter,
        // a fresh voter is admitted, and the cap is checked first.
        reset();
        let mut c = fresh_collection();
        c.state = State::Voting {
            started_at: CREATED,
        };
        c.votes = vec![vote(1, 200_000, true)];
        materialize(id, c, [9u8; 32]).unwrap();
        assert_eq!(
            vote_admits(&id, &[1; 32], 500),
            Err(StateError::Step(StepError::DuplicateVoter))
        );
        assert_eq!(vote_admits(&id, &[2; 32], 500), Ok(()));
        assert_eq!(vote_admits(&id, &[2; 32], 1), Err(StateError::VoteCapReached));
    }
}
