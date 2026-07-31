//! Frozen signed-message protocol (auction spec §Идентификаторы, §Методы).
//! `auction_id` (free scope of the auction) and `lot_id = sha256(auction_id ‖
//! text_hash)` (the per-lot scope) + the canonical wallet-signed messages. The
//! `two-outcome` verdict message and the Ed25519 check are shared crypto
//! (`crown-games-common`). Injective and byte-exact — pinned by the tests below.

use sha2::{Digest, Sha256};

// The verdict message (`domain ‖ program_id(32) ‖ u8(outcome)`) and the wallet
// signature check are identical across every `two-outcome` game — reused from
// `crown-games-common` so `protocol::verify` / `protocol::verdict_message` stay put.
pub use crown_games_common::wallet::{verdict_message, verify};

/// Domain of the wallet-signed messages.
pub const DOMAIN: &str = "crown:auction:v1";

const AUCTION_ID_PREFIX: &[u8] = b"crown:auction";

/// Free `scope_id` of an auction — recipient + nonce + the rules snapshot
/// (`duration` + `min_entry`), all committed so the canister recomputes and
/// verifies it at materialization. Does **not** commit any per-lot `text_hash`.
pub fn auction_id(
    canister: &[u8],
    recipient: [u8; 32],
    recipient_nonce: u64,
    duration: u64,
    min_entry: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(AUCTION_ID_PREFIX);
    h.update([canister.len() as u8]);
    h.update(canister);
    h.update(recipient);
    h.update(recipient_nonce.to_le_bytes());
    h.update(duration.to_le_bytes());
    h.update(min_entry.to_le_bytes());
    h.finalize().into()
}

/// Per-lot scope: `lot_id = sha256(auction_id ‖ text_hash)`. The escrow commits
/// transitively to the timings via `resolver → entry_id → lot_id → auction_id`.
/// A lot is the *contest* group (whose sums compete); it is **not** the settlement
/// scope — `return_entry` lets entries in one lot diverge.
pub fn lot_id(auction_id: &[u8; 32], text_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(auction_id);
    h.update(text_hash);
    h.finalize().into()
}

/// Per-entry settlement scope:
/// `entry_id = sha256(lot_id ‖ donor ‖ u64le(nonce) ‖ u64le(gross) ‖ i64le(deadline))`.
///
/// The resolver lives at the **entry** — the leaf where a settle/cancel decision
/// is actually made — so `resolver = key([entry_id])` names exactly one escrow and
/// a verdict can never be redeemed against a sibling entry.
///
/// **It must commit every field of the escrow's salt** (harness §4: a 1:1 scope
/// commits `gross`/`deadline`), and `gross`/`deadline` are exactly the two the
/// address derives from but a `(lot, donor, nonce)` triple does not. Without them
/// one donor could fund two escrows — same nonce, different amount or deadline
/// (`validate::deadline_ok` only bounds it from below) — that derive to two
/// distinct addresses and therefore both pass `DuplicateEscrow`, yet share one
/// `entry_id`, one resolver and one memoized verdict. A `return_entry` on the
/// small twin then yields a `Cancel` signature redeemable against the large one:
/// the donor takes the money back after the work was done. Committing them makes
/// the twins two scopes, so each buys its own verdict.
///
/// No derivation cycle: `gross`/`deadline` are fields the caller presents, and the
/// escrow address depends on them *through* the resolver — never the reverse.
/// Completes the scope hierarchy `auction_id → lot_id → entry_id`.
pub fn entry_id(
    lot_id: &[u8; 32],
    donor: &[u8; 32],
    nonce: u64,
    gross: u64,
    deadline: i64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(lot_id);
    h.update(donor);
    h.update(nonce.to_le_bytes());
    h.update(gross.to_le_bytes());
    h.update(deadline.to_le_bytes());
    h.finalize().into()
}

fn head(action: &str, chain: &str, canister: &str, auction_hex: &str) -> String {
    format!(
        "{DOMAIN}\naction: {action}\nchain: {chain}\ncanister: {canister}\nauction: {auction_hex}"
    )
}

/// `register` (donor signs) — commits to the lot's `text_hash` (its bid
/// condition); the birth proof and escrow fields ride as unsigned extras.
pub fn register_message(chain: &str, canister: &str, auction_hex: &str, text_hex: &str) -> String {
    format!(
        "{}\ntext: {}",
        head("register", chain, canister, auction_hex),
        text_hex
    )
}

/// A lot-scoped recipient action (`accept` / `return_lot`).
pub fn lot_message(
    action: &str,
    chain: &str,
    canister: &str,
    auction_hex: &str,
    lot_hex: &str,
) -> String {
    format!(
        "{}\nlot: {}",
        head(action, chain, canister, auction_hex),
        lot_hex
    )
}

/// `return_entry` (recipient signs) — returns one specific entry's escrow.
pub fn return_entry_message(
    chain: &str,
    canister: &str,
    auction_hex: &str,
    lot_hex: &str,
    entry_bs58: &str,
) -> String {
    format!(
        "{}\nlot: {}\nentry: {}",
        head("return_entry", chain, canister, auction_hex),
        lot_hex,
        entry_bs58
    )
}

/// An auction-scoped recipient action (`cancel`).
pub fn auction_message(action: &str, chain: &str, canister: &str, auction_hex: &str) -> String {
    head(action, chain, canister, auction_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn auction_id_is_byte_exact_and_commits_every_field() {
        let base = auction_id(b"cid", [1; 32], 5, 600, 0);
        let mut h = Sha256::new();
        h.update(b"crown:auction");
        h.update([3u8]);
        h.update(b"cid");
        h.update([1u8; 32]);
        h.update(5u64.to_le_bytes());
        h.update(600u64.to_le_bytes());
        h.update(0u64.to_le_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(base, expected);

        assert_ne!(base, auction_id(b"cid2", [1; 32], 5, 600, 0));
        assert_ne!(base, auction_id(b"cid", [9; 32], 5, 600, 0));
        assert_ne!(base, auction_id(b"cid", [1; 32], 6, 600, 0));
        assert_ne!(base, auction_id(b"cid", [1; 32], 5, 601, 0));
        assert_ne!(base, auction_id(b"cid", [1; 32], 5, 600, 1));
    }

    #[test]
    fn lot_id_binds_auction_and_text() {
        let a = auction_id(b"cid", [1; 32], 5, 600, 0);
        let base = lot_id(&a, &[7; 32]);
        assert_ne!(base, lot_id(&a, &[8; 32])); // different text
        let a2 = auction_id(b"cid", [2; 32], 5, 600, 0);
        assert_ne!(base, lot_id(&a2, &[7; 32])); // different auction
                                                 // Byte layout.
        let mut h = Sha256::new();
        h.update(a);
        h.update([7u8; 32]);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(base, expected);
    }

    #[test]
    fn entry_id_is_a_unique_leaf_scope_per_entry() {
        let lot = [7u8; 32];
        let base = entry_id(&lot, &[1; 32], 5, 1_000_000, 1_800_000_000);
        // Byte layout: sha256(lot ‖ donor ‖ u64le(nonce) ‖ u64le(gross) ‖ i64le(deadline)).
        let mut h = Sha256::new();
        h.update(lot);
        h.update([1u8; 32]);
        h.update(5u64.to_le_bytes());
        h.update(1_000_000u64.to_le_bytes());
        h.update(1_800_000_000i64.to_le_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(base, expected);
        // Every field moves the entry scope → distinct resolvers, no cross-entry
        // verdict redemption within a lot.
        assert_ne!(
            base,
            entry_id(&[8; 32], &[1; 32], 5, 1_000_000, 1_800_000_000)
        );
        assert_ne!(base, entry_id(&lot, &[2; 32], 5, 1_000_000, 1_800_000_000));
        assert_ne!(base, entry_id(&lot, &[1; 32], 6, 1_000_000, 1_800_000_000));
    }

    /// The entry scope must commit **every** field the escrow address derives
    /// from, or two escrows share one resolver and one verdict.
    ///
    /// `gross` and `deadline` are the two that a `(lot, donor, nonce)` triple
    /// misses while `crown_games_common::address::escrow_address` uses them. Twin
    /// escrows built on them derive to two distinct addresses — so both clear the
    /// `DuplicateEscrow` check, which compares addresses — and would otherwise
    /// land in the same scope: a `Cancel` bought for the cheap twin redeems
    /// against the expensive one.
    #[test]
    fn twin_escrows_differing_only_in_gross_or_deadline_are_distinct_scopes() {
        let lot = [7u8; 32];
        let donor = [1u8; 32];
        let base = entry_id(&lot, &donor, 5, 1_000_000, 1_800_000_000);
        // Same donor, same nonce, same lot — only the amount differs.
        assert_ne!(
            base,
            entry_id(&lot, &donor, 5, 1, 1_800_000_000),
            "a cheaper twin must not share the expensive entry's resolver"
        );
        // Same again — only the deadline differs (bounded from below only).
        assert_ne!(
            base,
            entry_id(&lot, &donor, 5, 1_000_000, 1_800_000_001),
            "a deadline+1 twin must not share the entry's resolver"
        );
    }

    #[test]
    fn messages_are_byte_exact() {
        assert_eq!(
            register_message("devnet", "aaaaa-aa", "ab", "cd"),
            "crown:auction:v1\naction: register\nchain: devnet\ncanister: aaaaa-aa\nauction: ab\ntext: cd"
        );
        assert_eq!(
            return_entry_message("devnet", "aaaaa-aa", "ab", "cd", "Esc"),
            "crown:auction:v1\naction: return_entry\nchain: devnet\ncanister: aaaaa-aa\nauction: ab\nlot: cd\nentry: Esc"
        );
        // The action is inside the signed bytes, so one signature never doubles
        // as another action's — the two returns in particular.
        assert_ne!(
            lot_message("accept", "devnet", "c", "a", "l"),
            lot_message("return_lot", "devnet", "c", "a", "l")
        );
        assert_ne!(
            auction_message("cancel", "devnet", "c", "a"),
            auction_message("cancel", "devnet", "c", "b")
        );
    }

    #[test]
    fn a_real_signature_verifies_and_tampering_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let msg = auction_message("cancel", "devnet", "aaaaa-aa", "auc1");
        let sig = sk.sign(msg.as_bytes()).to_bytes();
        assert!(verify(&msg, &pk, &sig));
        assert!(!verify(
            &auction_message("cancel", "devnet", "aaaaa-aa", "auc2"),
            &pk,
            &sig
        ));
    }
}
