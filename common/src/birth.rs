//! Birth proof — the witness half (harness §2, §4). A game is blind: a caller
//! presents the index's birth witness and the canister checks it *locally*
//! against a certified root — no RPC, no call to the index. This module verifies
//! the witness reconstructs to the root and extracts the birth leaf; the
//! certificate (BLS against the pinned NNS root key) that authenticates the root
//! is verified separately.
//!
//! Birth leaf layout (index `certified.rs`): `donor(32) ‖ u64le(slot)` — 40 bytes,
//! keyed by the escrow address under the `births` label. `gross` is deliberately
//! not stored: attribution reads only `donor`, and a consumer's escrow-address
//! derivation already commits `gross` (via the salt), so a birth proves *existence
//! + donor + slot* and nothing a fixed offset would have to guess per escrow form.

use ic_certification::{Certificate, HashTree, LookupResult};
use ic_verify_bls_signature::verify_bls_signature;

/// Raw BLS12-381 G2 public-key length; IC keys are DER-wrapped, the raw key is
/// the trailing 96 bytes.
const BLS_KEY_LEN: usize = 96;

/// The IC mainnet NNS root key — the trust anchor of every blind proof, and the
/// one constant here that is not ours: it is the published IC root key, taken
/// from the network itself (`/api/v2/status` of a boundary node) and cross-checked
/// against the value DFINITY ships in `ic-agent` (`IC_ROOT_KEY`). Both agree
/// byte for byte; a guessed constant would fail every proof closed, which reads
/// as "the boundary rejects everything for no reason".
///
/// DER-wrapped, 133 bytes: a 37-byte header (the IC's BLS12-381 OID pair) plus
/// the raw 96-byte G2 key the verifier strips off. Fixed-size on purpose —
/// an unset anchor is not expressible, so no game needs a runtime guard saying so.
///
/// One copy for all games: the key is shared with the frozen index's certificate,
/// and a diverged copy would silently fail every reputation and birth proof in
/// that one game (`crown-spec/docs/games-harness.md §6`).
pub const IC_MAINNET_ROOT_KEY: &[u8; 133] =
    b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\
      \x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\
      \x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\
      \x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\
      \x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\
      \x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

/// A recorded escrow birth, as proven by the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Birth {
    pub donor: [u8; 32],
    pub slot: u64,
}

/// Verify the index's certificate against the pinned NNS `root_key` (BLS, one
/// delegation level) and return the certified data (the combined root) for
/// `index_principal`. This is the root of trust of the blind birth proof.
///
/// **The certificate is authenticated, not dated** — there is no `/time` check,
/// so an old certificate stays acceptable. That is safe on exactly two standing
/// facts, and on nothing else: the book is monotone (a stale reputation proof
/// under-states a weight, never inflates it), and births are never pruned. The
/// day births start being pruned by terminality (`00-architecture.md §5`), a
/// stale certificate would prove a settled or refunded escrow still live — see
/// the trigger row in `crown-spec/docs/08-deferred.md`.
pub fn certified_root(
    cert_cbor: &[u8],
    root_key: &[u8],
    index_principal: &[u8],
) -> Option<[u8; 32]> {
    let cert: Certificate = serde_cbor::from_slice(cert_cbor).ok()?;
    verify_cert_signature(&cert, root_key, index_principal)?;
    let path = [
        b"canister".as_ref(),
        index_principal,
        b"certified_data".as_ref(),
    ];
    match cert.tree.lookup_path(path) {
        LookupResult::Found(root) => root.try_into().ok(),
        _ => None,
    }
}

/// Verify a certificate's BLS signature, resolving the signing key: either the
/// `root_key` directly, or — under a delegation — the subnet key the root key
/// certifies (a single delegation level, as the IC uses). Under a delegation the
/// index principal **must** fall inside the subnet's `canister_ranges`: without
/// that bind any subnet holding a valid NNS delegation for its own range could
/// sign a forged root for the index (forging births / reputation, and thus an
/// arbitrary settle/cancel).
fn verify_cert_signature(
    cert: &Certificate,
    root_key: &[u8],
    index_principal: &[u8],
) -> Option<()> {
    let signing_key = match &cert.delegation {
        None => root_key.to_vec(),
        Some(del) => {
            let del_cert: Certificate = serde_cbor::from_slice(del.certificate.as_ref()).ok()?;
            // NNS-signed delegation; the delegated subnet may only certify
            // canisters inside its own range.
            check_state_root_sig(&del_cert, root_key)?;
            let ranges = match del_cert.tree.lookup_path([
                b"subnet".as_ref(),
                del.subnet_id.as_ref(),
                b"canister_ranges".as_ref(),
            ]) {
                LookupResult::Found(r) => r,
                _ => return None,
            };
            if !principal_in_ranges(index_principal, ranges) {
                return None;
            }
            let path = [
                b"subnet".as_ref(),
                del.subnet_id.as_ref(),
                b"public_key".as_ref(),
            ];
            match del_cert.tree.lookup_path(path) {
                LookupResult::Found(k) => k.to_vec(),
                _ => return None,
            }
        }
    };
    check_state_root_sig(cert, &signing_key)
}

/// Whether `principal` falls inside one of the subnet's `canister_ranges`. The
/// leaf is CBOR: an array of `[start, end]` byte-string pairs (inclusive), and
/// principals order lexicographically by their raw bytes. Malformed CBOR → `false`.
fn principal_in_ranges(principal: &[u8], ranges_cbor: &[u8]) -> bool {
    let Ok(serde_cbor::Value::Array(ranges)) = serde_cbor::from_slice(ranges_cbor) else {
        return false;
    };
    ranges.iter().any(|range| {
        matches!(range,
            serde_cbor::Value::Array(pair)
            if matches!(pair.as_slice(),
                [serde_cbor::Value::Bytes(lo), serde_cbor::Value::Bytes(hi)]
                if lo.as_slice() <= principal && principal <= hi.as_slice()))
    })
}

/// BLS-verify a certificate's signature over `\x0Dic-state-root ‖ tree.digest()`
/// with `key` (DER or raw; the trailing 96 bytes are the raw G2 point).
fn check_state_root_sig(cert: &Certificate, key: &[u8]) -> Option<()> {
    let raw_key = key.get(key.len().checked_sub(BLS_KEY_LEN)?..)?;
    let mut msg = Vec::with_capacity(14 + 32);
    msg.push(13u8); // len("ic-state-root")
    msg.extend_from_slice(b"ic-state-root");
    msg.extend_from_slice(&cert.tree.digest());
    verify_bls_signature(cert.signature.as_ref(), &msg, raw_key).ok()
}

/// Verify a CBOR birth witness against `combined_root` and return the birth for
/// `escrow`, or `None` if the witness doesn't reconstruct to the root or the
/// escrow's leaf is absent/malformed. Pure and panic-free.
pub fn birth_from_witness(
    witness_cbor: &[u8],
    combined_root: &[u8; 32],
    escrow: &[u8; 32],
) -> Option<Birth> {
    let tree: HashTree = serde_cbor::from_slice(witness_cbor).ok()?;
    // The witness must reconstruct to exactly the certified combined root.
    if tree.digest() != *combined_root {
        return None;
    }
    // Extract the birth leaf at `["births", escrow]`.
    let leaf = match tree.lookup_path([b"births".as_ref(), escrow.as_ref()]) {
        LookupResult::Found(bytes) => bytes,
        _ => return None,
    };
    parse_birth_leaf(leaf)
}

/// Reputation proven for `(chain, donor, recipient)` against `combined_root`
/// (the book leaf is `u128le`). An absence proof means no reputation → `0`.
/// `None` only if the witness doesn't reconstruct to the root or is malformed.
pub fn reputation_from_witness(
    witness_cbor: &[u8],
    combined_root: &[u8; 32],
    chain: &[u8; 32],
    donor: &[u8; 32],
    recipient: &[u8; 32],
) -> Option<u128> {
    let tree: HashTree = serde_cbor::from_slice(witness_cbor).ok()?;
    if tree.digest() != *combined_root {
        return None;
    }
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(chain);
    key.extend_from_slice(donor);
    key.extend_from_slice(recipient);
    match tree.lookup_path([b"book".as_ref(), key.as_slice()]) {
        LookupResult::Found(v) => Some(u128::from_le_bytes(v.try_into().ok()?)),
        LookupResult::Absent => Some(0), // proven to have no reputation here
        _ => None,
    }
}

/// Parse a 40-byte birth leaf: `donor(32) ‖ u64le(slot)`.
fn parse_birth_leaf(leaf: &[u8]) -> Option<Birth> {
    let donor: [u8; 32] = leaf.get(0..32)?.try_into().ok()?;
    let slot = u64::from_le_bytes(leaf.get(32..40)?.try_into().ok()?);
    Some(Birth { donor, slot })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certified_map::{
        fork, fork_hash, labeled, labeled_hash, AsHashTree, HashTree as CmTree, RbTree,
    };

    // Labels must match the index's certified.rs exactly.
    const LABEL_BOOK: &[u8] = b"book";
    const LABEL_BIRTHS: &[u8] = b"births";

    /// Reproduce the index's birth leaf value.
    fn leaf_value(donor: [u8; 32], slot: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(40);
        v.extend_from_slice(&donor);
        v.extend_from_slice(&slot.to_le_bytes());
        v
    }

    /// Build the index's exact certified state for one birth and return
    /// `(combined_root, cbor(birth_witness))`.
    fn forge(escrow: [u8; 32], donor: [u8; 32], slot: u64) -> ([u8; 32], Vec<u8>) {
        // A book tree with an unrelated key, so its root is non-empty.
        let mut book: RbTree<Vec<u8>, Vec<u8>> = RbTree::new();
        book.insert(b"k".to_vec(), b"v".to_vec());
        let mut births: RbTree<Vec<u8>, Vec<u8>> = RbTree::new();
        births.insert(escrow.to_vec(), leaf_value(donor, slot));

        let combined = fork_hash(
            &labeled_hash(LABEL_BOOK, &book.root_hash()),
            &labeled_hash(LABEL_BIRTHS, &births.root_hash()),
        );
        let witness: CmTree = fork(
            CmTree::Pruned(labeled_hash(LABEL_BOOK, &book.root_hash())),
            labeled(LABEL_BIRTHS, births.witness(&escrow)),
        );
        let mut cbor = Vec::new();
        ciborium::into_writer(&witness, &mut cbor).unwrap();
        (combined, cbor)
    }

    #[test]
    fn a_genuine_witness_yields_the_birth() {
        let escrow = [5u8; 32];
        let (root, cbor) = forge(escrow, [1u8; 32], 42);
        let birth = birth_from_witness(&cbor, &root, &escrow).expect("proven");
        assert_eq!(birth.donor, [1u8; 32]);
        assert_eq!(birth.slot, 42);
    }

    #[test]
    fn a_wrong_root_is_rejected() {
        let escrow = [5u8; 32];
        let (mut root, cbor) = forge(escrow, [1u8; 32], 42);
        root[0] ^= 1; // tamper the expected root
        assert!(birth_from_witness(&cbor, &root, &escrow).is_none());
    }

    #[test]
    fn a_different_escrow_is_absent() {
        let escrow = [5u8; 32];
        let (root, cbor) = forge(escrow, [1u8; 32], 42);
        // The witness only proves `escrow`; another key is absent.
        assert!(birth_from_witness(&cbor, &root, &[6u8; 32]).is_none());
    }

    /// Build the index's exact certified state for a book (reputation) query and
    /// return `(combined_root, cbor(book_witness))`. `entry` is the reputation
    /// stored for `query`, or `None` for an empty book (an absence proof).
    fn forge_book(
        query: ([u8; 32], [u8; 32], [u8; 32]),
        entry: Option<u128>,
    ) -> ([u8; 32], Vec<u8>) {
        let key = |(c, d, r): ([u8; 32], [u8; 32], [u8; 32])| {
            let mut k = Vec::with_capacity(96);
            k.extend_from_slice(&c);
            k.extend_from_slice(&d);
            k.extend_from_slice(&r);
            k
        };
        let mut book: RbTree<Vec<u8>, Vec<u8>> = RbTree::new();
        if let Some(rep) = entry {
            book.insert(key(query), rep.to_le_bytes().to_vec());
        }
        let mut births: RbTree<Vec<u8>, Vec<u8>> = RbTree::new();
        births.insert(b"x".to_vec(), b"y".to_vec());

        let combined = fork_hash(
            &labeled_hash(LABEL_BOOK, &book.root_hash()),
            &labeled_hash(LABEL_BIRTHS, &births.root_hash()),
        );
        let witness: CmTree = fork(
            labeled(LABEL_BOOK, book.witness(&key(query))),
            CmTree::Pruned(labeled_hash(LABEL_BIRTHS, &births.root_hash())),
        );
        let mut cbor = Vec::new();
        ciborium::into_writer(&witness, &mut cbor).unwrap();
        (combined, cbor)
    }

    #[test]
    fn a_book_witness_proves_reputation() {
        let (c, d, r) = ([7u8; 32], [1u8; 32], [2u8; 32]);
        let (root, cbor) = forge_book((c, d, r), Some(750_000));
        assert_eq!(
            reputation_from_witness(&cbor, &root, &c, &d, &r),
            Some(750_000)
        );
    }

    #[test]
    fn an_absence_proof_is_zero_reputation() {
        let (c, d, r) = ([7u8; 32], [1u8; 32], [2u8; 32]);
        let (root, cbor) = forge_book((c, d, r), None); // empty book
        assert_eq!(reputation_from_witness(&cbor, &root, &c, &d, &r), Some(0));
    }

    /// CBOR-encode `canister_ranges` exactly as the IC does: an array of
    /// `[start, end]` byte-string pairs.
    fn ranges_cbor(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
        use serde_cbor::Value;
        let arr = pairs
            .iter()
            .map(|(lo, hi)| {
                Value::Array(vec![Value::Bytes(lo.to_vec()), Value::Bytes(hi.to_vec())])
            })
            .collect();
        serde_cbor::to_vec(&Value::Array(arr)).unwrap()
    }

    #[test]
    fn canister_ranges_bind_the_index_principal() {
        let ranges = ranges_cbor(&[(&[0x0A, 0x00], &[0x0A, 0xFF])]);
        // Inside, and both bounds inclusive.
        assert!(principal_in_ranges(&[0x0A, 0x7F], &ranges));
        assert!(principal_in_ranges(&[0x0A, 0x00], &ranges));
        assert!(principal_in_ranges(&[0x0A, 0xFF], &ranges));
        // Just outside either bound → rejected (the whole point: a subnet cannot
        // certify a principal outside its delegated range).
        assert!(!principal_in_ranges(&[0x09, 0xFF], &ranges));
        assert!(!principal_in_ranges(&[0x0B, 0x00], &ranges));
        // A second range still matches its own interval.
        let two = ranges_cbor(&[(&[0x01], &[0x01]), (&[0x0A, 0x00], &[0x0A, 0xFF])]);
        assert!(principal_in_ranges(&[0x01], &two));
        assert!(principal_in_ranges(&[0x0A, 0x10], &two));
        assert!(!principal_in_ranges(&[0x05], &two));
        // Malformed / empty CBOR → no match (fail closed).
        assert!(!principal_in_ranges(&[0x0A, 0x7F], b"not cbor"));
        assert!(!principal_in_ranges(&[0x0A, 0x7F], &ranges_cbor(&[])));
    }

    /// Pathologically nested CBOR is refused, not survived by luck.
    ///
    /// Every verifier here decodes attacker-chosen bytes into a **recursive**
    /// type (`HashTree` forks, `Certificate` trees), and both the decode and the
    /// `digest()`/`lookup_path` walks that follow are recursive too. The thing
    /// that makes this safe is a depth cap — `serde_cbor` refuses past 128 levels
    /// unless a caller explicitly opts out — and it is a *dependency default*,
    /// which is exactly the kind of load-bearing fact that disappears in a bump or
    /// a crate swap. `MAX_ARG_BYTES` alone would not do it: 8 KiB of the one-byte
    /// nesting header below is ~8 000 levels.
    ///
    /// So the property is asserted rather than assumed. Reaching this assertion at
    /// all is half the test: a run that blew the stack would not report a failure,
    /// it would abort.
    #[test]
    fn pathologically_nested_cbor_is_refused() {
        // `0x81` = a definite-length array of one element; repeat it and the value
        // nests once per byte. 8 KiB is the boundary's own argument cap, i.e. the
        // deepest thing a caller could ever get in front of these functions.
        let mut deep = vec![0x81u8; 8 * 1024];
        deep.push(0x00); // the innermost value
        let root = [0u8; 32];
        let id = [0u8; 32];
        assert!(birth_from_witness(&deep, &root, &id).is_none());
        assert!(reputation_from_witness(&deep, &root, &id, &id, &id).is_none());
        assert!(certified_root(&deep, IC_MAINNET_ROOT_KEY, &id).is_none());
    }

    #[test]
    fn malformed_bytes_never_panic() {
        // A blind game verifies attacker-supplied proofs on the hot path: every
        // public verifier must reject hostile bytes with `None`, never panic
        // (a panic on a poisoned proof would be a denial of service).
        let root = [0u8; 32];
        let id = [0u8; 32];
        let bads: [&[u8]; 5] = [b"", &[0xFF], b"not cbor", &[0u8; 64], &[0xA1; 128]];
        for bad in bads {
            assert!(birth_from_witness(bad, &root, &id).is_none());
            assert!(reputation_from_witness(bad, &root, &id, &id, &id).is_none());
            assert!(certified_root(bad, &[], &id).is_none()); // also: empty root key
        }
    }

    #[test]
    fn a_tampered_witness_does_not_reconstruct() {
        // Distinct from `a_wrong_root_is_rejected` (which tampers the expected
        // root): here the genuine root is kept and the *witness* is corrupted, so
        // it reconstructs to a different root → rejected (never the wrong birth).
        let escrow = [5u8; 32];
        let (root, cbor) = forge(escrow, [1u8; 32], 42);
        for i in 0..cbor.len() {
            let mut bad = cbor.clone();
            bad[i] ^= 0xFF;
            // Either the CBOR fails to decode or it reconstructs to a wrong root;
            // either way the genuine birth must never surface from a corrupt byte.
            assert_ne!(
                birth_from_witness(&bad, &root, &escrow),
                Some(Birth {
                    donor: [1u8; 32],
                    slot: 42
                })
            );
        }
    }

    #[test]
    fn the_pinned_nns_key_is_a_der_wrapped_bls_key() {
        // Guards the paste, not the value: the value is verified against the
        // network and against `ic-agent` out of band (see the constant's doc).
        // What can rot here is alignment — a truncated or re-indented literal
        // still compiles, and the damage (every proof failing closed on mainnet,
        // where `init` cannot override it) is silent. So: the DER header the IC
        // puts on every BLS key, and a raw key the verifier can strip whole.
        const DER_HEADER: &[u8] =
            b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\
            \x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
        assert_eq!(IC_MAINNET_ROOT_KEY.len(), DER_HEADER.len() + BLS_KEY_LEN);
        assert_eq!(&IC_MAINNET_ROOT_KEY[..DER_HEADER.len()], DER_HEADER);
    }
}
