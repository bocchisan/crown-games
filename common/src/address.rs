//! Escrow-address derivation for the `two-outcome` form (shared by every
//! class-B game). The `scope_id → resolver → address` chain has no cycle:
//! `scope_id` excludes `resolver`, the resolver is `key([scope_id])`, and the
//! address is the PDA of the salt built with that resolver. Pure — the same
//! `crown-salt`/`crown-derive` the form and indexer use, so a predicted address
//! matches the created escrow byte-for-byte.

/// Address of the `two-outcome` escrow for these birth fields under `resolver`.
/// `None` only if no off-curve PDA bump exists (astronomically unlikely).
#[allow(clippy::too_many_arguments)]
pub fn escrow_address(
    factory: [u8; 32],
    donor: [u8; 32],
    recipient: [u8; 32],
    gross: u64,
    deadline: i64,
    resolver: [u8; 32],
    fee_bps: u16,
    fee_wallet: [u8; 32],
    nonce: u64,
) -> Option<[u8; 32]> {
    let salt = crown_salt::two_outcome::two_outcome(
        donor, recipient, gross, deadline, resolver, fee_bps, fee_wallet, nonce,
    );
    crown_derive::solana_pda_address(factory, &[b"escrow", &salt]).map(|(addr, _bump)| addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn addr(
        factory: [u8; 32],
        donor: [u8; 32],
        recipient: [u8; 32],
        gross: u64,
        deadline: i64,
        resolver: [u8; 32],
        fee_bps: u16,
        fee_wallet: [u8; 32],
        nonce: u64,
    ) -> [u8; 32] {
        escrow_address(
            factory, donor, recipient, gross, deadline, resolver, fee_bps, fee_wallet, nonce,
        )
        .expect("a canonical PDA bump exists")
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = addr(
            [9; 32], [1; 32], [2; 32], 1000, 55, [4; 32], 300, [3; 32], 7,
        );
        let b = addr(
            [9; 32], [1; 32], [2; 32], 1000, 55, [4; 32], 300, [3; 32], 7,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn the_resolver_binds_the_address() {
        // Two scopes differ only in resolver (`key([scope_id])`) → different
        // escrow addresses, so the address is scope-bound.
        let a = addr(
            [9; 32], [1; 32], [2; 32], 1000, 55, [4; 32], 300, [3; 32], 7,
        );
        let b = addr(
            [9; 32], [1; 32], [2; 32], 1000, 55, [5; 32], 300, [3; 32], 7,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn every_salt_field_moves_the_address() {
        let base = addr(
            [9; 32], [1; 32], [2; 32], 1000, 55, [4; 32], 300, [3; 32], 7,
        );
        assert_ne!(
            base,
            addr([8; 32], [1; 32], [2; 32], 1000, 55, [4; 32], 300, [3; 32], 7)
        ); // factory
        assert_ne!(
            base,
            addr([9; 32], [0; 32], [2; 32], 1000, 55, [4; 32], 300, [3; 32], 7)
        ); // donor
        assert_ne!(
            base,
            addr([9; 32], [1; 32], [0; 32], 1000, 55, [4; 32], 300, [3; 32], 7)
        ); // recipient
        assert_ne!(
            base,
            addr([9; 32], [1; 32], [2; 32], 1001, 55, [4; 32], 300, [3; 32], 7)
        ); // gross
        assert_ne!(
            base,
            addr([9; 32], [1; 32], [2; 32], 1000, 56, [4; 32], 300, [3; 32], 7)
        ); // deadline
        assert_ne!(
            base,
            addr([9; 32], [1; 32], [2; 32], 1000, 55, [4; 32], 301, [3; 32], 7)
        ); // fee_bps
        assert_ne!(
            base,
            addr([9; 32], [1; 32], [2; 32], 1000, 55, [4; 32], 300, [0; 32], 7)
        ); // fee_wallet
        assert_ne!(
            base,
            addr([9; 32], [1; 32], [2; 32], 1000, 55, [4; 32], 300, [3; 32], 8)
        ); // nonce
    }
}
