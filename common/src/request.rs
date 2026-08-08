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
//!
//! **The domain line is checked, and until `P8` it was not.** Every game froze a
//! versioned domain (`crown:conditional-funding:v1`, …) as the message's first
//! line and specified it as such — but no verifier ever read it: the line carries
//! no `": "`, so [`parse_fields`] skips it, and each game's `target_ok` bound only
//! `canister` + `chain`. The consequence is the reason domain separation exists at
//! all: authorization was *any* signature over *any* text that happened to contain
//! the four lines `action:`/`chain:`/`canister:`/`collection:`. A wallet holder
//! talked into signing an unrelated challenge — a login nonce, a terms blob, some
//! other dApp's receipt — with those lines buried in it handed over a working
//! `recipient_cancel` (kills a live collection) or `vote`. Nothing else in the
//! request said which protocol the signature was for. Binding the first line
//! costs one comparison and is the cheapest check here, so it runs first.

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

/// Parse a request, bind it to `domain`, and verify the wallet signature over its
/// signed portion. `None` if malformed, if the signed message's first line is not
/// `domain`, or if the signature does not verify.
///
/// `domain` is the game's frozen `protocol::DOMAIN`. It is not a formality: it is
/// what makes the signature mean *this* protocol and *this* version of it rather
/// than "some text with the right lines in it" (see the module doc). Checked
/// before the Ed25519 verify — it is the cheaper of the two, and this parse runs
/// on the anonymous boundary.
pub fn parse(text: &str, domain: &str) -> Option<Request> {
    let (signed_msg, auth) = text.split_once(SEP)?;
    if signed_msg.lines().next()? != domain {
        return None;
    }
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

    const DOMAIN: &str = "crown:test:v1";
    const MSG: &str = "crown:test:v1\naction: go\nchain: devnet\nscope: abc";

    #[test]
    fn a_signed_request_parses_and_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let text = signed_request(&sk, MSG, &[]);
        let req = parse(&text, DOMAIN).expect("parses");
        assert_eq!(req.pubkey, sk.verifying_key().to_bytes());
        assert_eq!(req.signed("action"), Some("go"));
        assert_eq!(req.signed("scope"), Some("abc"));
    }

    #[test]
    fn extras_are_parsed_but_separate_from_signed() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let text = signed_request(&sk, MSG, &[("gross", "1860000"), ("nonce", "9")]);
        let req = parse(&text, DOMAIN).expect("parses");
        assert_eq!(req.extra("gross"), Some("1860000")); // unsigned
        assert_eq!(req.extra("nonce"), Some("9"));
        assert_eq!(req.signed("gross"), None, "extras are not signed fields");
    }

    #[test]
    fn a_tampered_message_fails_verification() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut text = signed_request(&sk, MSG, &[]);
        text = text.replace("action: go", "action: stop"); // signature no longer matches
        assert!(parse(&text, DOMAIN).is_none());
    }

    #[test]
    fn a_wrong_signer_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        // Sign with `sk` but present `other`'s pubkey.
        let sig = bs58::encode(sk.sign(MSG.as_bytes()).to_bytes()).into_string();
        let pk = bs58::encode(other.verifying_key().to_bytes()).into_string();
        let text = format!("{MSG}{SEP}pubkey: {pk}\nsignature: {sig}");
        assert!(parse(&text, DOMAIN).is_none());
    }

    #[test]
    fn a_missing_separator_or_auth_is_rejected() {
        assert!(parse("no separator here", DOMAIN).is_none());
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        assert!(parse(&format!("{MSG}{SEP}pubkey: {pk}"), DOMAIN).is_none()); // missing signature
    }

    /// The check the domain line exists for. A **genuine** signature — right key,
    /// right bytes — over text that is not this protocol's message must not
    /// authorize anything, however many of the right `key: value` lines it holds.
    ///
    /// This is the phishing shape, not a hypothetical: the fields below are
    /// exactly what a game's `admit_*` reads, so before the domain was bound, a
    /// wallet talked into signing the "login challenge" below produced a valid
    /// `cancel`/`vote` for a live scope.
    #[test]
    fn a_signature_over_foreign_text_authorizes_nothing() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let phish = "Sign in to Example\n\
                     Terms: https://example.invalid/tos\n\
                     action: go\n\
                     chain: devnet\n\
                     scope: abc\n\
                     Nonce: 8842";
        let text = signed_request(&sk, phish, &[]);
        // The signature itself is valid — that is the point.
        let sig: [u8; 64] = sk.sign(phish.as_bytes()).to_bytes();
        assert!(verify(phish, &sk.verifying_key().to_bytes(), &sig));
        assert!(
            parse(&text, DOMAIN).is_none(),
            "a signature over text that is not this protocol's message must not parse"
        );
    }

    /// A different game's (or a later version's) message is refused too — one
    /// domain, one protocol. The `canister` field already separates the games that
    /// exist today; the domain is what keeps that true when a message gains a
    /// field, a game is redeployed, or a fourth game reuses the framing.
    #[test]
    fn another_domain_is_refused() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let other = MSG.replace("crown:test:v1", "crown:test:v2");
        assert!(parse(&signed_request(&sk, &other, &[]), DOMAIN).is_none());
        assert!(parse(&signed_request(&sk, MSG, &[]), "crown:test:v2").is_none());
    }
}
