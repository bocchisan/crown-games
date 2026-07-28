//! Baked network config (`build.rs` from `../config/<profile>.toml`). Principals
//! are text (parsed at `init`); addresses are `[u8; 32]`. Nothing network in code.

include!(concat!(env!("OUT_DIR"), "/config.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_values_are_baked() {
        assert_eq!(PROFILE, "testnet");
        assert_eq!(CROWN_INDEX, "aaaaa-aa");
        assert_eq!(THRESHOLD_KEY, "dfx_test_key");
        assert_eq!(VOTING_PERIOD, 120);
        assert_eq!(MIN_GROSS, 1_860_000);
        assert_eq!(SIGN_PRICE, 26_200_000_000);
        assert_eq!(FEE_BPS, 300);
        assert_eq!(CHAIN_ID, "devnet");
        assert_eq!(DOMAIN, "crown:two-outcome:devnet");
        // fee_wallet / factory are still placeholders on testnet → unset.
        assert_eq!(FEE_WALLET, [0u8; 32]);
        assert_eq!(FACTORY, [0u8; 32]);
    }

    #[test]
    fn game_floor_is_at_least_index_min_gross() {
        // Alignment invariant (cost.md §6): the game floor must be ≥ the index's.
        let index_min_gross: u64 = 200_000;
        assert!(MIN_GROSS >= index_min_gross);
    }
}
