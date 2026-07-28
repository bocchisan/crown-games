//! Per-scope resolver (harness §4/§5). The resolver is `key([scope_id])` — a
//! threshold-Ed25519 subkey. A game canister caches the master public key + chain
//! code once (from `schnorr_public_key`) and derives every scope's resolver
//! *locally* with the IC's own derivation (`ic-ed25519`), so `get_resolver` is a
//! free `query` and no management call is made per scope. The derived key is both
//! the escrow's `resolver` field and what `sign_with_schnorr([scope_id])` signs
//! with — so the on-chain `resolver` and the verdict signer must match.

use ic_ed25519::{DerivationIndex, DerivationPath, PublicKey};

/// Derive the resolver `key([scope_id])` from the cached master key. `None` if the
/// master key bytes are not a valid Ed25519 point.
pub fn resolver(
    master_pk: &[u8],
    master_chain_code: &[u8; 32],
    scope_id: &[u8; 32],
) -> Option<[u8; 32]> {
    let master = PublicKey::deserialize_raw(master_pk).ok()?;
    let path = DerivationPath::new(vec![DerivationIndex(scope_id.to_vec())]);
    let (derived, _chain_code) = master.derive_subkey_with_chain_code(&path, master_chain_code);
    Some(derived.serialize_raw())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_ed25519::PrivateKey;

    /// The public-only derivation the canister does must yield the public key of
    /// the private subkey the threshold signers derive — otherwise the escrow's
    /// `resolver` field would not match the verdict signer.
    #[test]
    fn public_derivation_matches_private_derivation() {
        let master_sk = PrivateKey::deserialize_raw_32(&[7u8; 32]);
        let master_pk = master_sk.public_key().serialize_raw();
        let chain_code = [3u8; 32];
        let scope_id = [42u8; 32];

        let path = DerivationPath::new(vec![DerivationIndex(scope_id.to_vec())]);
        let (derived_sk, _cc) = master_sk.derive_subkey_with_chain_code(&path, &chain_code);
        let expected = derived_sk.public_key().serialize_raw();

        let got = resolver(&master_pk, &chain_code, &scope_id).expect("valid master");
        assert_eq!(got, expected);
    }

    #[test]
    fn distinct_scopes_get_distinct_resolvers() {
        let master_pk = PrivateKey::deserialize_raw_32(&[7u8; 32])
            .public_key()
            .serialize_raw();
        let cc = [0u8; 32];
        let a = resolver(&master_pk, &cc, &[1u8; 32]).unwrap();
        let b = resolver(&master_pk, &cc, &[2u8; 32]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_bad_master_key_is_rejected() {
        assert!(resolver(&[0u8; 10], &[0u8; 32], &[1u8; 32]).is_none());
    }
}
