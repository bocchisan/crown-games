//! Wallet-signature primitives shared by every game (harness §5, §7). The
//! authorization of a game action is the wallet's Ed25519 signature over the
//! canonical signed message (address ≡ pubkey), not the IC caller. `bs58_array`
//! decodes the fixed-width base58 fields (pubkey/signature/address) that appear
//! in those messages, and `verdict_message` is the frozen byte layout the
//! resolver signs — identical across every `two-outcome` game.

use ed25519_dalek::{Signature, VerifyingKey};

/// Verify an Ed25519 wallet signature over `message` (address ≡ pubkey, 32 B).
/// `verify_strict` (rejects small-order / non-canonical `R`), panic-free.
pub fn verify(message: &str, pubkey: &[u8; 32], signature: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk
            .verify_strict(message.as_bytes(), &Signature::from_bytes(signature))
            .is_ok(),
        Err(_) => false,
    }
}

/// bs58-decode into a fixed `[u8; N]`, or `None` on wrong length / bad base58.
pub fn bs58_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = bs58::decode(s).into_vec().ok()?;
    v.try_into().ok()
}

/// The verdict message the resolver signs (harness §5), byte-exact:
/// `domain ‖ program_id(32) ‖ u8(outcome)`. `outcome`: settle=0, refund/cancel=1.
///
/// The message names no escrow: an escrow is bound to its verdict solely through
/// **which key signs** (`resolver = key([scope_id])`). Law: a resolver key may be
/// shared across escrows only when they are guaranteed the *same* terminal
/// outcome, so `scope_id` must identify the finest unit that settles atomically —
/// a whole collection/task where the outcome is uniform, but a single **entry**
/// where siblings can diverge (auction `return_entry`). A scope drawn too broadly
/// makes a settle verdict redeemable against a sibling that should cancel.
pub fn verdict_message(domain: &str, program_id: &[u8; 32], outcome: u8) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len().saturating_add(33));
    m.extend_from_slice(domain.as_bytes());
    m.extend_from_slice(program_id);
    m.push(outcome);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn a_real_signature_verifies_and_tampering_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let msg = "crown:test\naction: ready";
        let sig = sk.sign(msg.as_bytes()).to_bytes();
        assert!(verify(msg, &pk, &sig));
        // Wrong message.
        assert!(!verify("crown:test\naction: cancel", &pk, &sig));
        // Tampered signature.
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(msg, &pk, &bad));
        // Wrong signer.
        let other = SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(!verify(msg, &other, &sig));
    }

    #[test]
    fn bs58_array_roundtrips_and_rejects_wrong_length() {
        let bytes = [3u8; 32];
        let s = bs58::encode(bytes).into_string();
        assert_eq!(bs58_array::<32>(&s), Some(bytes));
        assert_eq!(bs58_array::<64>(&s), None); // wrong width
        assert_eq!(bs58_array::<32>("0OIl"), None); // invalid base58 alphabet
    }

    #[test]
    fn verdict_message_is_byte_exact() {
        let program = [7u8; 32];
        let settle = verdict_message("crown:two-outcome:devnet", &program, 0);
        let mut expected = b"crown:two-outcome:devnet".to_vec();
        expected.extend_from_slice(&program);
        expected.push(0);
        assert_eq!(settle, expected);
        // Outcome byte flips the message.
        assert_ne!(
            settle,
            verdict_message("crown:two-outcome:devnet", &program, 1)
        );
    }
}
