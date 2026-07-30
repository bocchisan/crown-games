//! Field decoding and the shared canister constants — the small, identical parts
//! of every game's ingress path.
//!
//! Nothing here is clever. It is here because it was written out three times,
//! and drift had already started: one game's `now_secs` returned `i64` where the
//! others returned `u64`. Harmless there; [`chain_id`] below is the same shape of
//! duplication where it is not. (`now_secs` itself stays in the games — it is
//! three lines of `ic_cdk`, and this crate has no business depending on the CDK.)

/// `ChainId` exactly as `crown-indexer` keys the book: `sha256("crown-chain:v1:" ‖ id)`.
///
/// **Not a helper — the book key.** A game proves a voter's weight by walking the
/// index's hash tree to the leaf at `(chain, donor, recipient)`, so this hash has
/// to match the index's byte for byte. Get it wrong and every reputation proof in
/// that game fails to verify; the caller sees an unexplained refusal at the
/// boundary (`games-harness.md §6`) and nothing says why. It lived in three
/// copies plus the index's `build.rs` until `P7.6`.
pub fn chain_id(id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"crown-chain:v1:");
    h.update(id.as_bytes());
    h.finalize().into()
}

// ---- The boundary's argument cap, derived rather than picked ----
//
// The cap is a **cost knob, not a safety margin** — the same law the index states
// for `response_max_bytes` (`crown-indexer/src/config.rs`), on the other side of
// the system. Every *admitted* ingress is charged to the canister by the size it
// was allowed to be, so slack here is paid on every legitimate call and, worse, is
// the multiplier an attacker uses: the extras section is unsigned, so a valid
// message can be padded to the cap at no cost to the sender (`P7.15`).
//
// So it is computed from the format's worst case instead of rounded off. The
// asymmetry matters and sets which way to err: too large costs money per message
// (bounded, and visible in the cycle burn); **too small silently drops valid
// registrations at the boundary, which looks to the client like a refusal with no
// reason.** Hence a deliberate 2× headroom over the model below.

/// Levels of the index's keyed-Merkle tree at generation capacity — `log2` of
/// ~5.99M book keys (`crown-indexer/docs/spec.md §Ёмкость`, after `P7.10`),
/// rounded up. The witness grows with the book, so the bound has to be taken at
/// the capacity the generation can actually reach, **not** measured on today's
/// nearly empty devnet book: a cap fitted to a small tree works for months and
/// then starts refusing real calls.
const TREE_DEPTH_AT_CAPACITY: usize = 23;

/// One pruned sibling on the wire: a CBOR `[4, h'..32 bytes..']`.
const PRUNED_NODE_BYTES: usize = 32 + 4;
/// CBOR framing of one `Fork` on the path.
const FORK_BYTES: usize = 3;
/// Labels, the leaf value, and the outer fork over the two sub-trees
/// (`book`/`births`) plus its pruned sibling — the book key is the widest label
/// at `chain ‖ donor ‖ recipient` = 96 bytes.
const WITNESS_FIXED_BYTES: usize = 96 + 32 + PRUNED_NODE_BYTES + 32;

/// One witness, hex-encoded as it travels in the request extras (hex doubles it —
/// the single largest term, and the one an eyeball estimate forgets).
const WITNESS_BYTES: usize =
    2 * (TREE_DEPTH_AT_CAPACITY * (PRUNED_NODE_BYTES + FORK_BYTES) + WITNESS_FIXED_BYTES);

/// The signed message, the bs58 pubkey/signature pair, and the field names around
/// them. Generous: the longest signed message across the three games is well under
/// this.
const ENVELOPE_BYTES: usize = 1024;

/// The most bytes a legitimate request can need: at most one witness (registration
/// carries exactly one since `P7.14`; a vote carries exactly one) plus envelope.
const REQUEST_WORST_CASE: usize = WITNESS_BYTES + ENVELOPE_BYTES;

/// Largest ingress argument any game accepts — cut first on the boundary, before
/// any parse or hex-decode, so a multi-megabyte flood is never even read.
///
/// 8 KiB: the modelled worst case with room to spare, and the same number the
/// relay guards with (`crown-relay/src/lib.rs`), which the old comment here
/// claimed while the constant said 32 KiB.
pub const MAX_ARG_BYTES: usize = 8 * 1024;

// The headroom is a law, not a hope: if the model ever grows past half the cap,
// this stops compiling rather than silently starting to refuse valid calls.
const _: () = assert!(
    REQUEST_WORST_CASE * 2 <= MAX_ARG_BYTES,
    "the argument cap must keep 2× headroom over the worst legitimate request — \
     under-sizing it drops valid registrations at the boundary, invisibly"
);

/// Cap of votes per scope (non-negativity invariant #7; `cost.md §6` `V_MAX`) —
/// the ceiling on what an unprofitable scope can cost in vote traffic.
pub const V_MAX: usize = 500;

pub fn u64_of(s: Option<&str>) -> Option<u64> {
    s?.parse().ok()
}
pub fn i64_of(s: Option<&str>) -> Option<i64> {
    s?.parse().ok()
}
// `u128_of` and `bool_of` lived here for the recipient profile's `min_reputation`
// and `enabled`. The profile is gone (`P7.14`) and no wire field is a `u128` or a
// bool any more, so they went with it rather than staying as a parser nobody
// calls (`CLAUDE.md §Минимализм`).

/// A 32-byte value from a hex field. Takes `&str` so it composes as
/// `req.signed("x").and_then(field::hex32)`, which is how every call site reads.
pub fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}
/// Raw bytes from a hex field (witnesses, certificates).
pub fn hex_bytes(s: Option<&str>) -> Option<Vec<u8>> {
    hex::decode(s?).ok()
}
/// The `choice` field of a vote: `done` / `not_done`. Anything else is malformed
/// rather than a default — a vote whose meaning is guessed is a vote miscounted.
pub fn choice(c: &str) -> Option<bool> {
    match c {
        "done" => Some(true),
        "not_done" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one value here that must equal something outside this crate: the
    /// index's baked `CHAIN_ID` (`crown-indexer/build.rs`, same derivation).
    #[test]
    fn chain_id_is_the_index_derivation() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"crown-chain:v1:");
        h.update(b"devnet");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(chain_id("devnet"), expected);
        // Different clusters are different universes (`00 §2`).
        assert_ne!(chain_id("devnet"), chain_id("mainnet"));
    }

    #[test]
    fn fields_decode_or_refuse() {
        assert_eq!(u64_of(Some("42")), Some(42));
        assert_eq!(u64_of(Some("-1")), None);
        assert_eq!(u64_of(None), None);
        assert_eq!(i64_of(Some("-1")), Some(-1));
        assert_eq!(hex32(&"ab".repeat(32)), Some([0xabu8; 32]));
        assert_eq!(hex32("ab"), None, "wrong length is not padded");
        assert_eq!(hex_bytes(Some("00ff")), Some(vec![0x00, 0xff]));
        assert_eq!(hex_bytes(Some("zz")), None);
        assert_eq!(choice("done"), Some(true));
        assert_eq!(choice("not_done"), Some(false));
        assert_eq!(choice("maybe"), None, "an unknown choice is not a default");
    }
}
