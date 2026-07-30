//! Frozen signed-message protocol (tasks spec §Область, §Форматы). `task_id`
//! derivation + the canonical wallet-signed messages + Ed25519 verification.
//! The encoding is injective and byte-exact — pinned by the unit tests below.

use sha2::{Digest, Sha256};

/// Domain of the wallet-signed messages (distinct from the `task_id` prefix).
pub const DOMAIN: &str = "crown:conditional-tasks:v1";

/// Prefix of the `task_id` preimage (no `:v1` — the id is versioned by the
/// preimage layout, not the message domain).
const TASK_ID_PREFIX: &[u8] = b"crown:conditional-tasks";

/// Free `scope_id` of a task — the escrow-salt inputs *minus* `resolver`, plus
/// the canister id and the timings (§Область). Commits `gross` and `deadline`
/// (1:1 task↔escrow). Never the escrow address (that depends on the resolver,
/// the resolver on this id — otherwise a cycle).
#[allow(clippy::too_many_arguments)]
pub fn task_id(
    canister: &[u8],
    donor: [u8; 32],
    recipient: [u8; 32],
    gross: u64,
    deadline: i64,
    fee_bps: u16,
    fee_wallet: [u8; 32],
    nonce: u64,
    duration: u64,
    voting_period: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TASK_ID_PREFIX);
    h.update([canister.len() as u8]); // principals are <= 29 bytes
    h.update(canister);
    h.update(donor);
    h.update(recipient);
    h.update(gross.to_le_bytes());
    h.update(deadline.to_le_bytes());
    h.update(fee_bps.to_le_bytes());
    h.update(fee_wallet);
    h.update(nonce.to_le_bytes());
    h.update(duration.to_le_bytes());
    h.update(voting_period.to_le_bytes());
    h.finalize().into()
}

/// The common head of a task message: domain, action, chain, canister, task.
fn head(action: &str, chain: &str, canister: &str, task: &str) -> String {
    format!("{DOMAIN}\naction: {action}\nchain: {chain}\ncanister: {canister}\ntask: {task}")
}

/// `register` message (donor signs): adds `text` (hex of the text hash) and the
/// `duration` the donor commits to.
pub fn register_message(
    chain: &str,
    canister: &str,
    task_bs58: &str,
    text_hash_hex: &str,
    duration: u64,
) -> String {
    format!(
        "{}\ntext: {}\nduration: {}",
        head("register", chain, canister, task_bs58),
        text_hash_hex,
        duration
    )
}

pub fn accept_message(chain: &str, canister: &str, task_bs58: &str) -> String {
    head("accept", chain, canister, task_bs58)
}

pub fn decline_message(chain: &str, canister: &str, task_bs58: &str) -> String {
    head("decline", chain, canister, task_bs58)
}

pub fn ready_message(chain: &str, canister: &str, task_bs58: &str) -> String {
    head("ready", chain, canister, task_bs58)
}

/// `vote` message: adds `choice` (`done`/`not_done`).
pub fn vote_message(chain: &str, canister: &str, task_bs58: &str, choice: &str) -> String {
    format!(
        "{}\nchoice: {}",
        head("vote", chain, canister, task_bs58),
        choice
    )
}

// There is no `set-profile` message: the recipient's acceptance terms are a
// client-side filter, not canister state (`P7.14`, `state.rs`).

// The verdict message (`domain ‖ program_id(32) ‖ u8(outcome)`) and the Ed25519
// wallet-signature check are the same across every `two-outcome` game — they live
// in `crown-games-common`. Re-exported so `protocol::verify` / `protocol::
// verdict_message` call sites and tests stay unchanged.
pub use crown_games_common::wallet::{verdict_message, verify};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn task_id_is_byte_exact_and_commits_every_field() {
        let base = task_id(
            b"canister",
            [1; 32],
            [2; 32],
            1000,
            55,
            300,
            [3; 32],
            7,
            600,
            120,
        );
        // A hand-rolled reference of the exact preimage.
        let mut h = Sha256::new();
        h.update(b"crown:conditional-tasks");
        h.update([8u8]); // len("canister")
        h.update(b"canister");
        h.update([1u8; 32]);
        h.update([2u8; 32]);
        h.update(1000u64.to_le_bytes());
        h.update(55i64.to_le_bytes());
        h.update(300u16.to_le_bytes());
        h.update([3u8; 32]);
        h.update(7u64.to_le_bytes());
        h.update(600u64.to_le_bytes());
        h.update(120u64.to_le_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(base, expected);

        // Every field changes the id (a spot-check of injectivity).
        assert_ne!(
            base,
            task_id(
                b"canister2",
                [1; 32],
                [2; 32],
                1000,
                55,
                300,
                [3; 32],
                7,
                600,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [9; 32],
                [2; 32],
                1000,
                55,
                300,
                [3; 32],
                7,
                600,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [1; 32],
                [9; 32],
                1000,
                55,
                300,
                [3; 32],
                7,
                600,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [1; 32],
                [2; 32],
                1001,
                55,
                300,
                [3; 32],
                7,
                600,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [1; 32],
                [2; 32],
                1000,
                56,
                300,
                [3; 32],
                7,
                600,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [1; 32],
                [2; 32],
                1000,
                55,
                301,
                [3; 32],
                7,
                600,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [1; 32],
                [2; 32],
                1000,
                55,
                300,
                [9; 32],
                7,
                600,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [1; 32],
                [2; 32],
                1000,
                55,
                300,
                [3; 32],
                8,
                600,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [1; 32],
                [2; 32],
                1000,
                55,
                300,
                [3; 32],
                7,
                601,
                120
            )
        );
        assert_ne!(
            base,
            task_id(
                b"canister",
                [1; 32],
                [2; 32],
                1000,
                55,
                300,
                [3; 32],
                7,
                600,
                121
            )
        );
    }

    #[test]
    fn length_prefix_defeats_canister_donor_ambiguity() {
        // Without a length prefix, ("ab", donor=cd..) and ("abcd", ..) could
        // collide. The `u8(len)` makes the preimage injective.
        let a = task_id(b"ab", [0xcd; 32], [2; 32], 1, 1, 1, [3; 32], 1, 1, 1);
        let b = task_id(b"abcd", [0; 32], [2; 32], 1, 1, 1, [3; 32], 1, 1, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn messages_are_byte_exact() {
        assert_eq!(
            register_message("devnet", "aaaaa-aa", "T", "ab12", 3600),
            "crown:conditional-tasks:v1\naction: register\nchain: devnet\ncanister: aaaaa-aa\ntask: T\ntext: ab12\nduration: 3600"
        );
        assert_eq!(
            accept_message("devnet", "aaaaa-aa", "T"),
            "crown:conditional-tasks:v1\naction: accept\nchain: devnet\ncanister: aaaaa-aa\ntask: T"
        );
        assert_eq!(
            vote_message("devnet", "aaaaa-aa", "T", "done"),
            "crown:conditional-tasks:v1\naction: vote\nchain: devnet\ncanister: aaaaa-aa\ntask: T\nchoice: done"
        );
    }

    #[test]
    fn distinct_actions_and_fields_give_distinct_messages() {
        let a = accept_message("devnet", "c", "T");
        assert_ne!(a, decline_message("devnet", "c", "T"));
        assert_ne!(a, ready_message("devnet", "c", "T"));
        assert_ne!(
            accept_message("devnet", "c", "T1"),
            accept_message("devnet", "c", "T2")
        );
        assert_ne!(
            vote_message("devnet", "c", "T", "done"),
            vote_message("devnet", "c", "T", "not_done")
        );
    }

    #[test]
    fn a_real_signature_verifies_and_tampering_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let msg = accept_message("devnet", "aaaaa-aa", "task123");
        let sig = sk.sign(msg.as_bytes()).to_bytes();

        assert!(verify(&msg, &pk, &sig));
        // A different message under the same signature fails.
        assert!(!verify(
            &decline_message("devnet", "aaaaa-aa", "task123"),
            &pk,
            &sig
        ));
        // A flipped signature byte fails.
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&msg, &pk, &bad));
        // A wrong signer fails.
        let other = SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(!verify(&msg, &other, &sig));
    }

    #[test]
    fn verdict_message_is_byte_exact() {
        let program = [7u8; 32];
        let m = verdict_message("crown:two-outcome:devnet", &program, 0);
        // domain bytes ‖ program_id(32) ‖ outcome(1).
        let mut expected = b"crown:two-outcome:devnet".to_vec();
        expected.extend_from_slice(&program);
        expected.push(0);
        assert_eq!(m, expected);
        assert_eq!(m.len(), 24 + 32 + 1);
        // Settle (0) and cancel (1) differ only in the last byte.
        let cancel = verdict_message("crown:two-outcome:devnet", &program, 1);
        assert_eq!(cancel[..cancel.len() - 1], m[..m.len() - 1]);
        assert_ne!(cancel, m);
    }

    /// The one thing the framing tests in `crown_games_common::request` cannot
    /// say: that *this game's* messages survive it. Everything else about the
    /// wire format — the separator, the auth extraction, tampering, a wrong
    /// signer — is one security boundary and is tested once, there.
    #[test]
    fn a_real_register_message_round_trips_the_shared_wire_format() {
        use crown_games_common::request::parse;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let msg = register_message("devnet", "aaaaa-aa", "T", "ab", 3600);
        let pk = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        let sig = bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string();
        let text = format!("{msg}\n---\npubkey: {pk}\nsignature: {sig}\ngross: 1860000\nnonce: 9");

        let req = parse(&text).expect("a real register message parses");
        assert_eq!(req.pubkey, sk.verifying_key().to_bytes());
        assert_eq!(req.signed("action"), Some("register"));
        assert_eq!(req.signed("duration"), Some("3600"));
        // Registration fields ride unsigned and must stay out of the signed map —
        // they are cross-checked against the birth proof, never trusted here.
        assert_eq!(req.extra("gross"), Some("1860000"));
        assert_eq!(req.signed("gross"), None);
    }
}
