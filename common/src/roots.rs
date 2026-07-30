//! The game-side cache of authenticated index roots — the split that keeps the
//! anonymous boundary affordable.
//!
//! Trust in the index is one certificate check plus one hash-tree walk. The
//! certificate costs two BLS pairings (the index's signature plus the subnet
//! delegation), which is far past the 200M-instruction budget of
//! `inspect_message`: verified per call, a valid registration could not be
//! admitted at all. So the two halves are split by who pays. Authenticating a
//! root is a paid pull (`push_root`, `ROOT_PRICE`) that runs the pairings once
//! and [`remember`]s the result; every per-caller proof afterwards — birth or
//! reputation — is a walk against that cache ([`birth`], [`reputation`]),
//! O(log n), which the boundary can afford (`cost.md §6` #2,
//! `games-harness.md §6`).
//!
//! The policy lives here rather than in a game because it is one mechanism, not
//! a per-game choice: the cache depth, the eviction order and the walk-against-
//! any-root rule must be identical everywhere, or the boundary's cost — and the
//! width of the stale-root window — would differ per game. Each canister owns
//! the `Vec` (it is canister state) and its own paid endpoint (the result enums
//! differ); the delicate part is these functions.

use crate::birth::{birth_from_witness, reputation_from_witness, Birth};

/// How many certified index roots stay admissible at once. The index root moves
/// with every `ingest`, so a witness built against the root that was current
/// when the caller assembled it must still verify while the next `push_root`
/// lands. Small on purpose: an old root is a window in which a since-corrected
/// book state stays provable.
pub const ROOT_CACHE: usize = 4;

/// Record `root` as the newest admissible root, evicting the oldest past
/// [`ROOT_CACHE`].
///
/// Re-pushing a root already cached only refreshes its position and never grows
/// the cache — otherwise replaying one certificate would evict every other live
/// root, and witnesses built against them would start failing for free.
pub fn remember(roots: &mut Vec<[u8; 32]>, root: [u8; 32]) {
    if let Some(pos) = roots.iter().position(|r| *r == root) {
        let r = roots.remove(pos);
        roots.push(r);
        return;
    }
    if roots.len() == ROOT_CACHE {
        roots.remove(0); // evict the oldest
    }
    roots.push(root);
}

/// The birth of `escrow` proven by `witness_cbor` against any cached root,
/// with the root it verified under.
///
/// The caller gets the matched root back so a second witness in the same request
/// (the registrant's reputation) is checked against the *same* root: two proofs
/// admitted under two different roots would mix two book states.
///
/// Newest root first — the common case is the freshest one. A witness
/// reconstructs to exactly one root, so at most one can match.
pub fn birth(
    roots: &[[u8; 32]],
    witness_cbor: &[u8],
    escrow: &[u8; 32],
) -> Option<([u8; 32], Birth)> {
    roots
        .iter()
        .rev()
        .find_map(|root| birth_from_witness(witness_cbor, root, escrow).map(|b| (*root, b)))
}

/// Reputation for `(chain, donor, recipient)` proven by `witness_cbor` against
/// any cached root. `None` means no root admits the witness — an unprovable
/// claim, not a zero one (a *proven* absence is `Some(0)`, per
/// [`reputation_from_witness`]).
pub fn reputation(
    roots: &[[u8; 32]],
    witness_cbor: &[u8],
    chain: &[u8; 32],
    donor: &[u8; 32],
    recipient: &[u8; 32],
) -> Option<u128> {
    roots
        .iter()
        .rev()
        .find_map(|root| reputation_from_witness(witness_cbor, root, chain, donor, recipient))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certified_map::{
        fork, fork_hash, labeled, labeled_hash, AsHashTree, HashTree as CmTree, RbTree,
    };

    const LABEL_BOOK: &[u8] = b"book";
    const LABEL_BIRTHS: &[u8] = b"births";

    /// Reproduce the index's certified state for one birth and one book entry,
    /// returning `(combined_root, cbor(birth_witness), cbor(book_witness))`.
    fn forge(
        escrow: [u8; 32],
        donor: [u8; 32],
        slot: u64,
        recipient: [u8; 32],
        chain: [u8; 32],
        reputation: u128,
    ) -> ([u8; 32], Vec<u8>, Vec<u8>) {
        let mut key = Vec::with_capacity(96);
        key.extend_from_slice(&chain);
        key.extend_from_slice(&donor);
        key.extend_from_slice(&recipient);

        let mut book: RbTree<Vec<u8>, Vec<u8>> = RbTree::new();
        book.insert(key.clone(), reputation.to_le_bytes().to_vec());
        let mut births: RbTree<Vec<u8>, Vec<u8>> = RbTree::new();
        let mut leaf = Vec::with_capacity(40);
        leaf.extend_from_slice(&donor);
        leaf.extend_from_slice(&slot.to_le_bytes());
        births.insert(escrow.to_vec(), leaf);

        let combined = fork_hash(
            &labeled_hash(LABEL_BOOK, &book.root_hash()),
            &labeled_hash(LABEL_BIRTHS, &births.root_hash()),
        );
        let birth_witness: CmTree = fork(
            CmTree::Pruned(labeled_hash(LABEL_BOOK, &book.root_hash())),
            labeled(LABEL_BIRTHS, births.witness(&escrow)),
        );
        let book_witness: CmTree = fork(
            labeled(LABEL_BOOK, book.witness(&key)),
            CmTree::Pruned(labeled_hash(LABEL_BIRTHS, &births.root_hash())),
        );
        let mut birth_cbor = Vec::new();
        ciborium::into_writer(&birth_witness, &mut birth_cbor).unwrap();
        let mut book_cbor = Vec::new();
        ciborium::into_writer(&book_witness, &mut book_cbor).unwrap();
        (combined, birth_cbor, book_cbor)
    }

    /// Measure, rather than assume, how many **distinct** subsequent pushes a
    /// witness survives: push the victim's root, then keep pushing others until
    /// the victim's witness stops verifying, and report the count.
    fn survived_foreign_pushes(escrow: [u8; 32], victim_root: [u8; 32], witness: &[u8]) -> usize {
        let mut roots = vec![victim_root];
        assert!(
            birth(&roots, witness, &escrow).is_some(),
            "the victim's own root must admit it to begin with"
        );
        for k in 1..64u32 {
            // A distinct root each time — one per other client, or per replayed
            // certificate; the cache cannot tell those apart.
            let mut r = [0u8; 32];
            r[..4].copy_from_slice(&k.to_be_bytes());
            r[31] = 0xAA;
            remember(&mut roots, r);
            if birth(&roots, witness, &escrow).is_none() {
                return (k - 1) as usize;
            }
        }
        panic!("the witness never stopped verifying — the cache does not evict");
    }

    /// **Measurement (not a policy assertion).** A proof is admissible for exactly
    /// `ROOT_CACHE - 1` distinct pushes after the one that carried its root, and
    /// the cache cannot tell *who* pushed: four other honest clients evict a
    /// witness exactly as four replayed certificates do. So this number is not an
    /// attack surface first — it is a **concurrency ceiling**: more than
    /// `ROOT_CACHE` participants preparing claims against distinct roots at once
    /// will start knocking each other out, with no adversary present.
    ///
    /// The certificate that carries a root is authenticated but **not dated**
    /// (`birth::certified_root`), so an old certificate is replayable for free —
    /// which is what lets the same mechanism be driven deliberately. The fix, if
    /// one is ever needed, is not a bigger cache: raising `ROOT_CACHE` widens the
    /// window in which a since-corrected book state stays provable, at exactly the
    /// same rate.
    #[test]
    fn measure_how_many_pushes_a_proof_survives() {
        let escrow = [5u8; 32];
        let (root, birth_cbor, _) = forge(escrow, [1u8; 32], 42, [7u8; 32], [9u8; 32], 0);
        let survived = survived_foreign_pushes(escrow, root, &birth_cbor);
        assert_eq!(
            survived,
            ROOT_CACHE - 1,
            "a proof survives ROOT_CACHE-1 distinct pushes; measured {survived}"
        );

        // The victim can hold their slot — but only by paying `ROOT_PRICE` again
        // for a root that is already authenticated, once per would-be evictor.
        let mut roots = vec![root];
        for k in 0..(ROOT_CACHE as u8 * 3) {
            remember(&mut roots, [k; 32]);
            remember(&mut roots, root); // re-push refreshes to newest
        }
        assert!(
            birth(&roots, &birth_cbor, &escrow).is_some(),
            "re-pushing the same root keeps a proof alive indefinitely"
        );
    }

    #[test]
    fn the_cache_keeps_the_newest_and_evicts_the_oldest() {
        let mut roots = Vec::new();
        for i in 0..(ROOT_CACHE as u8 + 2) {
            remember(&mut roots, [i; 32]);
        }
        assert_eq!(roots.len(), ROOT_CACHE);
        // The two oldest are gone, the newest is last.
        assert_eq!(roots.first(), Some(&[2u8; 32]));
        assert_eq!(roots.last(), Some(&[ROOT_CACHE as u8 + 1; 32]));
    }

    #[test]
    fn re_pushing_a_cached_root_refreshes_it_without_evicting() {
        let mut roots = Vec::new();
        for i in 0..ROOT_CACHE as u8 {
            remember(&mut roots, [i; 32]);
        }
        // Replaying the oldest must not push anything out: a replayed
        // certificate would otherwise clear the cache one root at a time.
        remember(&mut roots, [0u8; 32]);
        assert_eq!(roots.len(), ROOT_CACHE);
        assert_eq!(roots.last(), Some(&[0u8; 32]));
        for i in 1..ROOT_CACHE as u8 {
            assert!(roots.contains(&[i; 32]));
        }
    }

    #[test]
    fn a_witness_verifies_against_any_cached_root() {
        let escrow = [5u8; 32];
        let (root, birth_cbor, _) = forge(escrow, [1u8; 32], 42, [7u8; 32], [9u8; 32], 0);
        // The genuine root sits behind three newer ones — it must still admit.
        let mut roots = vec![root];
        for i in 0..3u8 {
            remember(&mut roots, [i; 32]);
        }
        let (matched, b) = birth(&roots, &birth_cbor, &escrow).expect("proven");
        assert_eq!(matched, root);
        assert_eq!(b.donor, [1u8; 32]);
        assert_eq!(b.slot, 42);
    }

    #[test]
    fn a_witness_whose_root_was_evicted_is_refused() {
        let escrow = [5u8; 32];
        let (root, birth_cbor, _) = forge(escrow, [1u8; 32], 42, [7u8; 32], [9u8; 32], 0);
        let mut roots = vec![root];
        for i in 0..ROOT_CACHE as u8 {
            remember(&mut roots, [i; 32]); // pushes `root` out
        }
        assert!(!roots.contains(&root));
        assert!(birth(&roots, &birth_cbor, &escrow).is_none());
    }

    #[test]
    fn an_empty_cache_admits_nothing() {
        let escrow = [5u8; 32];
        let (_, birth_cbor, book_cbor) = forge(escrow, [1u8; 32], 42, [7u8; 32], [9u8; 32], 500);
        // Before the first `push_root` every proof is unprovable — never a
        // silent zero weight, which would read as a valid sub-threshold vote.
        assert!(birth(&[], &birth_cbor, &escrow).is_none());
        assert!(reputation(&[], &book_cbor, &[9u8; 32], &[1u8; 32], &[7u8; 32]).is_none());
    }

    #[test]
    fn reputation_verifies_against_a_cached_root() {
        let (root, _, book_cbor) = forge([5u8; 32], [1u8; 32], 42, [7u8; 32], [9u8; 32], 500);
        let roots = vec![root];
        assert_eq!(
            reputation(&roots, &book_cbor, &[9u8; 32], &[1u8; 32], &[7u8; 32]),
            Some(500)
        );
        // A pair the witness proves *absent* is a genuine zero, not a failure —
        // the caller may prove they have no reputation. `MIN_VOTE_WEIGHT`, not
        // this function, is what turns that into a refusal.
        assert_eq!(
            reputation(&roots, &book_cbor, &[9u8; 32], &[2u8; 32], &[7u8; 32]),
            Some(0)
        );
    }
}
