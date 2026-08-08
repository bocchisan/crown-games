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

// The verdict signature store and its claim-before-await discipline live in
// `crown_games_common::signing` — non-negativity invariant #5, one mechanism
// for every game rather than three byte-identical copies (`P7.6`).
pub use crown_games_common::signing::SignedVerdict;

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

/// Time-free boundary pre-check for a recipient action (harness §6), the twin of
/// [`vote_admits`]: unknown collection, wrong signer, or a stored state whose
/// transition table does not admit the action.
///
/// Sound on the time-free boundary for the same reason `vote_admits` is: the only
/// move time can make is into `Decided`, which admits nothing, so an action the
/// stored state refuses is refused in every state time could have produced
/// (`conditional_funding_logic::State::admits`, pinned to `apply_action` by an
/// exhaustive test). A strict subset of `recipient_action`'s rejections, which
/// stays the authoritative gate.
///
/// Without this the boundary admitted every action from the right signer and left
/// the refusal to the update — so a doomed `ready` could be repeated forever and
/// executed replicated each time, free for the sender and billed to the canister.
pub fn action_admits(
    collection_id: &[u8; 32],
    signer: &[u8; 32],
    action: &Action,
) -> Result<(), StateError> {
    COLLECTIONS.with_borrow(|c| {
        let s = c.get(collection_id).ok_or(StateError::NotFound)?;
        if s.recipient != *signer {
            return Err(StateError::NotRecipient);
        }
        if !s.collection.state.admits(action) {
            return Err(StateError::Step(StepError::InvalidTransition));
        }
        Ok(())
    })
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

/// A materialized collection as `get_collection` reads it: the state at `now`
/// plus the window this collection actually runs on.
///
/// The anchors are here because a donor needs them and has nowhere else to get
/// them. A contribution's escrow must be born with
/// `deadline >= created_at + duration + voting_period + DEADLINE_MARGIN` — the
/// spec assigns that arithmetic to the donor's client, and the canister checks it
/// only for the one contribution that materialized the collection; every later
/// one is a member by deriving the resolver and is never seen here. Until these
/// fields were published the client had to *guess* `created_at`: `collection_id`
/// is a hash, so the recipient and the window are not recoverable from it, and a
/// guess that lands early makes the escrow refundable before the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    pub state: State,
    pub created_at: u64,
    pub duration: u64,
    pub voting_period: u64,
    pub recipient: [u8; 32],
}

/// The materialized collection (with accrued time transitions applied at `now`
/// via a `Tick`), or `None` if unknown.
pub fn collection_view(collection_id: &[u8; 32], now: u64) -> Option<View> {
    COLLECTIONS.with_borrow_mut(|c| {
        let s = c.get_mut(collection_id)?;
        let _ = step(&mut s.collection, Action::Tick, now); // apply accrued transitions
        Some(View {
            state: s.collection.state,
            created_at: s.collection.created_at,
            duration: s.collection.duration,
            voting_period: s.collection.voting_period,
            recipient: s.recipient,
        })
    })
}

/// The materialized collection's state alone (same lazy `Tick`).
pub fn collection_state(collection_id: &[u8; 32], now: u64) -> Option<State> {
    collection_view(collection_id, now).map(|v| v.state)
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
        crown_games_common::signing::reset_for_test();
    }

    // The signature store's own behaviour — repeat served free, one claim at a
    // time, an aborted signing left retriable — is tested once, in
    // `crown_games_common::signing`. Re-testing it per game re-tested one
    // mechanism three times and told us nothing about this game (`P7.6`).

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

    /// The boundary must refuse a doomed recipient action, not leave it to the
    /// update — otherwise one signed `ready` is a flood template billed to us.
    #[test]
    fn action_admits_refuses_what_the_state_will_refuse() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];

        assert_eq!(
            action_admits(&id, &recipient, &Action::Ready),
            Err(StateError::NotFound)
        );

        materialize(id, fresh_collection(), recipient).unwrap();
        assert_eq!(
            action_admits(&id, &[8u8; 32], &Action::Ready),
            Err(StateError::NotRecipient)
        );
        // `Funding` admits both recipient actions.
        assert_eq!(action_admits(&id, &recipient, &Action::Ready), Ok(()));
        assert_eq!(
            action_admits(&id, &recipient, &Action::RecipientCancel),
            Ok(())
        );

        // After `ready` the collection is `Voting`: both are doomed and now die
        // here rather than being executed and refused by the update.
        recipient_action(&id, &recipient, Action::Ready, CREATED).unwrap();
        for a in [Action::Ready, Action::RecipientCancel] {
            assert_eq!(
                action_admits(&id, &recipient, &a),
                Err(StateError::Step(StepError::InvalidTransition)),
                "{a:?} must be refused once voting has opened"
            );
        }

        // Decided is absorbing.
        reset();
        materialize(id, fresh_collection(), recipient).unwrap();
        recipient_action(&id, &recipient, Action::RecipientCancel, CREATED).unwrap();
        for a in [Action::Ready, Action::RecipientCancel] {
            assert_eq!(
                action_admits(&id, &recipient, &a),
                Err(StateError::Step(StepError::InvalidTransition)),
                "{a:?} must be refused on a decided collection"
            );
        }
    }

    /// Every boundary rejection must be one the update would also make, or a
    /// legitimate call is dropped for free and reads as a refusal without cause.
    #[test]
    fn action_admits_never_refuses_what_the_update_would_accept() {
        for action in [Action::Ready, Action::RecipientCancel] {
            reset();
            let id = [1u8; 32];
            let recipient = [9u8; 32];
            materialize(id, fresh_collection(), recipient).unwrap();
            assert_eq!(
                action_admits(&id, &recipient, &action),
                Ok(()),
                "boundary refused {action:?}, which the update accepts"
            );
            assert!(
                recipient_action(&id, &recipient, action.clone(), CREATED).is_ok(),
                "update refused {action:?} the boundary admitted"
            );
        }
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
        assert_eq!(
            vote_admits(&id, &[2; 32], 1),
            Err(StateError::VoteCapReached)
        );
    }
}
