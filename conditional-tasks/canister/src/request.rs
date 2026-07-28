//! Wire format of a signed request. The `text` argument of every update is the
//! canonical signed message (the frozen `protocol` format), a `\n---\n`
//! separator, then the wallet auth and any unsigned extras:
//!
//! ```text
//! crown:conditional-tasks:v1
//! action: accept
//! …signed fields…
//! ---
//! pubkey: <bs58(32)>
//! signature: <bs58(64)>
//! …unsigned extras (register fields, birth proof)…
//! ```
//!
//! The signed portion is verified against `pubkey` (authorization is the wallet
//! signature, not the caller — harness §7). Extras are never trusted for
//! authorization; they are cross-checked against the birth proof by the caller.
//!
//! The framing/auth/verification are game-agnostic and live in
//! `crown-games-common`; re-exported here so `request::parse`/`request::Request`/
//! `request::bs58_array` call sites stay unchanged. The tests below pin the
//! behaviour against the *tasks* protocol messages specifically.

pub use crown_games_common::request::{parse, Request};
pub use crown_games_common::wallet::bs58_array;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol;
    use ed25519_dalek::{Signer, SigningKey};

    const SEP: &str = "\n---\n";

    /// Build a signed request text: `<message>\n---\npubkey:..\nsignature:..\n<extras>`.
    fn signed_request(sk: &SigningKey, message: &str, extras: &[(&str, &str)]) -> String {
        let pk = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        let sig = bs58::encode(sk.sign(message.as_bytes()).to_bytes()).into_string();
        let mut out = format!("{message}{SEP}pubkey: {pk}\nsignature: {sig}");
        for (k, v) in extras {
            out.push_str(&format!("\n{k}: {v}"));
        }
        out
    }

    #[test]
    fn a_signed_request_parses_and_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let msg = protocol::accept_message("devnet", "aaaaa-aa", "task123");
        let text = signed_request(&sk, &msg, &[]);

        let req = parse(&text).expect("parses");
        assert_eq!(req.pubkey, sk.verifying_key().to_bytes());
        assert_eq!(req.signed("action"), Some("accept"));
        assert_eq!(req.signed("chain"), Some("devnet"));
        assert_eq!(req.signed("task"), Some("task123"));
    }

    #[test]
    fn extras_are_parsed_but_separate_from_signed() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let msg = protocol::register_message("devnet", "aaaaa-aa", "T", "ab", 3600);
        let text = signed_request(&sk, &msg, &[("gross", "1860000"), ("nonce", "9")]);

        let req = parse(&text).expect("parses");
        assert_eq!(req.signed("duration"), Some("3600")); // signed
        assert_eq!(req.extra("gross"), Some("1860000")); // unsigned
        assert_eq!(req.extra("nonce"), Some("9"));
        assert_eq!(req.signed("gross"), None, "extras are not signed fields");
    }

    #[test]
    fn a_tampered_message_fails_verification() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let msg = protocol::accept_message("devnet", "aaaaa-aa", "task123");
        let mut text = signed_request(&sk, &msg, &[]);
        // Flip the action in the signed portion (signature no longer matches).
        text = text.replace("action: accept", "action: decline");
        assert!(parse(&text).is_none());
    }

    #[test]
    fn a_wrong_signer_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let msg = protocol::accept_message("devnet", "aaaaa-aa", "task123");
        // Sign with `sk` but present `other`'s pubkey.
        let sig = bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string();
        let pk = bs58::encode(other.verifying_key().to_bytes()).into_string();
        let text = format!("{msg}{SEP}pubkey: {pk}\nsignature: {sig}");
        assert!(parse(&text).is_none());
    }

    #[test]
    fn a_missing_separator_or_auth_is_rejected() {
        assert!(parse("no separator here").is_none());
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let msg = protocol::accept_message("devnet", "c", "t");
        // Missing signature line.
        let pk = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        assert!(parse(&format!("{msg}{SEP}pubkey: {pk}")).is_none());
    }
}
