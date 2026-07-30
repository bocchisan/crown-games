//! Verdict-signature memoization — non-negativity invariant #5 (`cost.md §6`),
//! one mechanism for every game.
//!
//! A scope's verdict signature is deterministic in `(scope_id, outcome)` and the
//! outcome is immutable once decided (harness §8), so a repeat request is the
//! *same* bytes. Buying them twice would burn `SIGN_PRICE` for nothing, and the
//! "amortization `s/N`" the economics rest on would be a possibility rather than
//! a fact: the second escrow of a scope would pay full price for a signature that
//! already exists.
//!
//! Two rules, and both are the invariant rather than an optimization:
//!
//! 1. **A produced signature is stored and served free** — the game's
//!    `get_signature` is a `query`, and `request_signature` answers from
//!    [`cached`] *before* it looks at the attached cycles.
//! 2. **The right to sign is claimed synchronously, before the `await`** — the
//!    store only lands after it, so without the claim N concurrent requests for
//!    one scope would each miss the cache and each pay.
//!
//! The state lives here rather than in each game because the crate is linked into
//! every game canister separately: each gets its own maps, and the *policy* has
//! one copy. It was three byte-identical copies before `P7.6`, differing only in
//! what the scope was called (`task_id` / `collection_id` / `entry_scope`) — and
//! a drift between them would not have shown up as a failing test but as a
//! cycle bill.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

/// A produced verdict signature: `(outcome, signature)`. `outcome` is the form's
/// index (`two-outcome`: settle=0, cancel/refund=1) — never an address, so it
/// proves nothing on-chain by itself.
pub type SignedVerdict = (u8, Vec<u8>);

thread_local! {
    /// Verdict signatures already produced, keyed by the scope whose resolver
    /// signed them (`derivation_path = [scope_id]`).
    static SIGNATURES: RefCell<BTreeMap<[u8; 32], SignedVerdict>> =
        const { RefCell::new(BTreeMap::new()) };
    /// Scopes with a `sign_with_schnorr` in flight, claimed synchronously before
    /// the await so concurrent siblings do not each pay for the same signature.
    static IN_FLIGHT: RefCell<BTreeSet<[u8; 32]>> = const { RefCell::new(BTreeSet::new()) };
}

/// The signature already produced for a scope, if any. Free — served from store
/// instead of bought again.
pub fn cached(scope: &[u8; 32]) -> Option<SignedVerdict> {
    SIGNATURES.with_borrow(|s| s.get(scope).cloned())
}

/// Claim the right to sign `scope`, *synchronously* before the await. `false`
/// when a sibling call already holds the claim. Released by [`store`] (success)
/// or [`release`] (abort).
pub fn claim(scope: [u8; 32]) -> bool {
    IN_FLIGHT.with_borrow_mut(|s| s.insert(scope))
}

/// Record a produced signature and drop the in-flight claim.
pub fn store(scope: [u8; 32], outcome: u8, signature: Vec<u8>) {
    IN_FLIGHT.with_borrow_mut(|s| s.remove(&scope));
    SIGNATURES.with_borrow_mut(|s| s.insert(scope, (outcome, signature)));
}

/// Drop a claim whose signing failed, keeping the scope retriable.
pub fn release(scope: &[u8; 32]) {
    IN_FLIGHT.with_borrow_mut(|s| s.remove(scope));
}

/// Clear both maps. Test-only: canister state is per-instance in production, but
/// a test binary shares one thread_local across its cases.
pub fn reset_for_test() {
    SIGNATURES.with_borrow_mut(BTreeMap::clear);
    IN_FLIGHT.with_borrow_mut(BTreeSet::clear);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_signature_is_served_free_and_forever() {
        reset_for_test();
        let scope = [1u8; 32];
        assert!(cached(&scope).is_none());
        store(scope, 0, vec![9u8; 64]);
        // The bytes come back without a claim, a price, or a second signing.
        assert_eq!(cached(&scope), Some((0u8, vec![9u8; 64])));
        assert_eq!(cached(&scope), Some((0u8, vec![9u8; 64])));
    }

    #[test]
    fn the_claim_is_what_stops_n_callers_paying_for_one_signature() {
        reset_for_test();
        let scope = [2u8; 32];
        assert!(claim(scope), "the first caller signs");
        assert!(!claim(scope), "a concurrent sibling must not also pay");
        assert!(!claim(scope));
        // Storing the result frees the claim and answers everyone from cache.
        store(scope, 1, vec![7u8; 64]);
        assert_eq!(cached(&scope), Some((1u8, vec![7u8; 64])));
    }

    #[test]
    fn a_failed_signing_leaves_the_scope_retriable() {
        reset_for_test();
        let scope = [3u8; 32];
        assert!(claim(scope));
        release(&scope); // sign_with_schnorr rejected
        assert!(cached(&scope).is_none(), "nothing was produced");
        assert!(claim(scope), "the next caller may try again");
    }

    #[test]
    fn scopes_are_independent() {
        reset_for_test();
        assert!(claim([4u8; 32]));
        assert!(claim([5u8; 32]), "one scope's claim never blocks another");
        store([4u8; 32], 0, vec![1u8; 64]);
        assert!(cached(&[5u8; 32]).is_none());
    }
}
