//! Wire framing of a signed request, shared by every game (harness §7). The
//! `text` argument of every update is the canonical signed message (the game's
//! frozen `protocol` format), a `\n---\n` separator, then the wallet auth and any
//! unsigned extras:
//!
//! ```text
//! crown:conditional-<game>:v1
//! action: <action>
//! …signed fields…
//! ---
//! pubkey: <bs58(32)>
//! signature: <bs58(64)>
//! …unsigned extras (register / birth-proof fields)…
//! ```
//!
//! The signed portion is verified against `pubkey` (authorization is the wallet
//! signature, not the IC caller). Extras are never trusted for authorization;
//! the caller cross-checks them against the birth proof. The signed message's
//! wording is game-specific and lives in each game's `protocol`; the framing,
//! the auth extraction, and the signature check are the same everywhere and live
//! here — a single security boundary, not one copy per game.

use crate::wallet::{bs58_array, verify};
use std::collections::BTreeMap;

const SEP: &str = "\n---\n";

/// A parsed, signature-verified request.
pub struct Request {
    /// Fields of the signed message (`action`, `chain`, `canister`, `scope`, …).
    pub signed: BTreeMap<String, String>,
    /// Fields of the unsigned auth/extras section.
    pub extra: BTreeMap<String, String>,
    /// The wallet that signed (address ≡ pubkey).
    pub pubkey: [u8; 32],
}

impl Request {
    /// A signed field, if present.
    pub fn signed(&self, key: &str) -> Option<&str> {
        self.signed.get(key).map(String::as_str)
    }
    /// An unsigned extra field, if present.
    pub fn extra(&self, key: &str) -> Option<&str> {
        self.extra.get(key).map(String::as_str)
    }
}

/// Parse a request and verify the wallet signature over its signed portion.
/// `None` if malformed or the signature does not verify.
pub fn parse(text: &str) -> Option<Request> {
    let (signed_msg, auth) = text.split_once(SEP)?;
    let extra = parse_fields(auth);
    let pubkey = bs58_array::<32>(extra.get("pubkey")?)?;
    let signature = bs58_array::<64>(extra.get("signature")?)?;
    if !verify(signed_msg, &pubkey, &signature) {
        return None;
    }
    Some(Request {
        signed: parse_fields(signed_msg),
        extra,
        pubkey,
    })
}

/// Parse `key: value` lines into a map (the domain line, having no `": "`, is
/// skipped). Values never contain `": "` (bs58/hex/decimal), so this is exact.
fn parse_fields(s: &str) -> BTreeMap<String, String> {
    s.lines()
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

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

    const MSG: &str = "crown:test:v1\naction: go\nchain: devnet\nscope: abc";

    #[test]
    fn a_signed_request_parses_and_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let text = signed_request(&sk, MSG, &[]);
        let req = parse(&text).expect("parses");
        assert_eq!(req.pubkey, sk.verifying_key().to_bytes());
        assert_eq!(req.signed("action"), Some("go"));
        assert_eq!(req.signed("scope"), Some("abc"));
    }

    #[test]
    fn extras_are_parsed_but_separate_from_signed() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let text = signed_request(&sk, MSG, &[("gross", "1860000"), ("nonce", "9")]);
        let req = parse(&text).expect("parses");
        assert_eq!(req.extra("gross"), Some("1860000")); // unsigned
        assert_eq!(req.extra("nonce"), Some("9"));
        assert_eq!(req.signed("gross"), None, "extras are not signed fields");
    }

    #[test]
    fn a_tampered_message_fails_verification() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut text = signed_request(&sk, MSG, &[]);
        text = text.replace("action: go", "action: stop"); // signature no longer matches
        assert!(parse(&text).is_none());
    }

    #[test]
    fn a_wrong_signer_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        // Sign with `sk` but present `other`'s pubkey.
        let sig = bs58::encode(sk.sign(MSG.as_bytes()).to_bytes()).into_string();
        let pk = bs58::encode(other.verifying_key().to_bytes()).into_string();
        let text = format!("{MSG}{SEP}pubkey: {pk}\nsignature: {sig}");
        assert!(parse(&text).is_none());
    }

    #[test]
    fn a_missing_separator_or_auth_is_rejected() {
        assert!(parse("no separator here").is_none());
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        assert!(parse(&format!("{MSG}{SEP}pubkey: {pk}")).is_none()); // missing signature
    }
}
