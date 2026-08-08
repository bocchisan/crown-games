//! Frozen signed-message protocol (funding spec §Область, §Форматы сообщений).
//! `collection_id` derivation + the canonical wallet-signed messages + Ed25519
//! verification + the verdict message. Injective and byte-exact — pinned below.

use sha2::{Digest, Sha256};

// The verdict message (`domain ‖ program_id(32) ‖ u8(outcome) ‖ u16le(fee_bps) ‖
// fee_wallet(32)`) and the Ed25519 wallet-signature check are identical across
// every `two-outcome` game — they live in `crown-games-common`. Re-exported so
// `protocol::verify` / `protocol::verdict_message` call sites stay unchanged.
pub use crown_games_common::wallet::{verdict_message, verify};

/// Domain of the wallet-signed messages.
pub const DOMAIN: &str = "crown:conditional-funding:v1";

const COLLECTION_ID_PREFIX: &[u8] = b"crown:conditional-funding";

/// Free `scope_id` of a collection (§Область) — recipient + nonce + the rules
/// snapshot (timings, verdict params). Unlike a task it does **not** commit
/// `gross`/`deadline` (many escrows per collection); `recipient_nonce` only
/// disambiguates the id.
#[allow(clippy::too_many_arguments)]
pub fn collection_id(
    canister: &[u8],
    recipient: [u8; 32],
    recipient_nonce: u64,
    duration: u64,
    voting_period: u64,
    approval_threshold: u16,
    quorum_weight: u128,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COLLECTION_ID_PREFIX);
    h.update([canister.len() as u8]);
    h.update(canister);
    h.update(recipient);
    h.update(recipient_nonce.to_le_bytes());
    h.update(duration.to_le_bytes());
    h.update(voting_period.to_le_bytes());
    h.update(approval_threshold.to_le_bytes());
    h.update(quorum_weight.to_le_bytes());
    h.finalize().into()
}

fn head(action: &str, chain: &str, canister: &str, collection: &str) -> String {
    format!("{DOMAIN}\naction: {action}\nchain: {chain}\ncanister: {canister}\ncollection: {collection}")
}

/// `create` message (recipient signs) — adds the `goal` and `duration`.
pub fn create_message(
    chain: &str,
    canister: &str,
    collection_hex: &str,
    goal: u128,
    duration: u64,
) -> String {
    format!(
        "{}\ngoal: {}\nduration: {}",
        head("create", chain, canister, collection_hex),
        goal,
        duration
    )
}

pub fn ready_message(chain: &str, canister: &str, collection_hex: &str) -> String {
    head("ready", chain, canister, collection_hex)
}

pub fn cancel_message(chain: &str, canister: &str, collection_hex: &str) -> String {
    head("cancel", chain, canister, collection_hex)
}

/// `vote` message — adds `choice` (`done`/`not_done`).
pub fn vote_message(chain: &str, canister: &str, collection_hex: &str, choice: &str) -> String {
    format!(
        "{}\nchoice: {}",
        head("vote", chain, canister, collection_hex),
        choice
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn collection_id_is_byte_exact_and_commits_every_field() {
        let base = collection_id(b"cid", [1; 32], 5, 600, 120, 5_000, 150_000);
        let mut h = Sha256::new();
        h.update(b"crown:conditional-funding");
        h.update([3u8]); // len("cid")
        h.update(b"cid");
        h.update([1u8; 32]);
        h.update(5u64.to_le_bytes());
        h.update(600u64.to_le_bytes());
        h.update(120u64.to_le_bytes());
        h.update(5_000u16.to_le_bytes());
        h.update(150_000u128.to_le_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(base, expected);

        assert_ne!(
            base,
            collection_id(b"cid2", [1; 32], 5, 600, 120, 5_000, 150_000)
        );
        assert_ne!(
            base,
            collection_id(b"cid", [9; 32], 5, 600, 120, 5_000, 150_000)
        );
        assert_ne!(
            base,
            collection_id(b"cid", [1; 32], 6, 600, 120, 5_000, 150_000)
        );
        assert_ne!(
            base,
            collection_id(b"cid", [1; 32], 5, 601, 120, 5_000, 150_000)
        );
        assert_ne!(
            base,
            collection_id(b"cid", [1; 32], 5, 600, 121, 5_000, 150_000)
        );
        assert_ne!(
            base,
            collection_id(b"cid", [1; 32], 5, 600, 120, 5_001, 150_000)
        );
        assert_ne!(
            base,
            collection_id(b"cid", [1; 32], 5, 600, 120, 5_000, 150_001)
        );
    }

    #[test]
    fn messages_are_byte_exact() {
        assert_eq!(
            create_message("devnet", "aaaaa-aa", "ab12", 5_000_000, 600),
            "crown:conditional-funding:v1\naction: create\nchain: devnet\ncanister: aaaaa-aa\ncollection: ab12\ngoal: 5000000\nduration: 600"
        );
        assert_eq!(
            vote_message("devnet", "aaaaa-aa", "ab12", "done"),
            "crown:conditional-funding:v1\naction: vote\nchain: devnet\ncanister: aaaaa-aa\ncollection: ab12\nchoice: done"
        );
        assert_ne!(
            ready_message("devnet", "c", "x"),
            cancel_message("devnet", "c", "x")
        );
    }

    #[test]
    fn verdict_message_is_byte_exact() {
        let program = [7u8; 32];
        let wallet = [4u8; 32];
        let m = verdict_message("crown:two-outcome:devnet", &program, 0, 300, &wallet);
        let mut expected = b"crown:two-outcome:devnet".to_vec();
        expected.extend_from_slice(&program);
        expected.push(0);
        expected.extend_from_slice(&300u16.to_le_bytes());
        expected.extend_from_slice(&wallet);
        assert_eq!(m, expected);
    }

    /// The fee binding matters most here: a collection's membership **is** the
    /// shared resolver, so contributions after the first are never seen by this
    /// canister at all. Signing the config price list is what stops one of them
    /// from settling under the collection's verdict at `fee_bps = 0`
    /// (harness §9, `crown-games-common::wallet`).
    #[test]
    fn the_signed_verdict_carries_this_games_own_fee() {
        let program = crate::config::FACTORY;
        let signed = verdict_message(
            crate::config::DOMAIN,
            &program,
            0,
            crate::config::FEE_BPS,
            &crate::config::FEE_WALLET,
        );
        assert_ne!(
            signed,
            verdict_message(
                crate::config::DOMAIN,
                &program,
                0,
                0,
                &crate::config::FEE_WALLET
            ),
            "a fee-free contribution must not share the collection's verdict message"
        );
    }

    #[test]
    fn a_real_signature_verifies_and_tampering_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let msg = ready_message("devnet", "aaaaa-aa", "col1");
        let sig = sk.sign(msg.as_bytes()).to_bytes();
        assert!(verify(&msg, &pk, &sig));
        assert!(!verify(
            &cancel_message("devnet", "aaaaa-aa", "col1"),
            &pk,
            &sig
        ));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&msg, &pk, &bad));
    }
}
