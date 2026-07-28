//! Baked network config (`build.rs` from `../config/<profile>.toml`). Principals
//! are text (parsed at `init`); addresses are `[u8; 32]`. Nothing network in code.
//! No `min_gross`: a collection's contributions are free-floating, the floor is
//! amortized across `N` donors (funding spec §Константы).

include!(concat!(env!("OUT_DIR"), "/config.rs"));

/// Convert a Solana birth `slot` to the collection's `created_at` (unix seconds)
/// by the pinned linear anchor (funding spec §Тайминги: "slot→time by a pinned
/// `SLOTS_PER_SECOND`"; `SLOT_MS = 1000 / SLOTS_PER_SECOND`). Isolated here so the
/// one delicate time mapping has a single home. Checked; `None` if the slot
/// precedes the anchor or the arithmetic overflows. The anchor (`GENESIS_SLOT`,
/// `GENESIS_UNIX`) is a per-cluster network constant — a placeholder until
/// F5(devnet)/P8(mainnet), like the factory address.
pub fn slot_to_created_at(slot: u64) -> Option<u64> {
    let elapsed_slots = slot.checked_sub(GENESIS_SLOT)?;
    let elapsed_ms = elapsed_slots.checked_mul(SLOT_MS)?;
    GENESIS_UNIX.checked_add(elapsed_ms / 1_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use conditional_funding_logic::{MIN_APPROVAL_THRESHOLD, MIN_VOTE_WEIGHT};

    #[test]
    fn testnet_values_are_baked() {
        assert_eq!(PROFILE, "testnet");
        assert_eq!(CROWN_INDEX, "aaaaa-aa");
        assert_eq!(THRESHOLD_KEY, "dfx_test_key");
        assert_eq!(VOTING_PERIOD, 120);
        assert_eq!(APPROVAL_THRESHOLD, 5_000);
        assert_eq!(QUORUM_WEIGHT, 150_000);
        assert_eq!(SIGN_PRICE, 26_200_000_000);
        assert_eq!(FEE_BPS, 300);
        assert_eq!(CHAIN_ID, "devnet");
        assert_eq!(DOMAIN, "crown:two-outcome:devnet");
        assert_eq!(SLOT_MS, 400);
        // fee_wallet / factory / slot→time anchor are placeholders on testnet.
        assert_eq!(FEE_WALLET, [0u8; 32]);
        assert_eq!(FACTORY, [0u8; 32]);
        assert_eq!(GENESIS_SLOT, 0);
        assert_eq!(GENESIS_UNIX, 0);
    }

    #[test]
    fn slot_to_created_at_is_linear_and_checked() {
        // With the anchor (genesis 0/0, slot_ms 400): elapsed_ms = slot·400,
        // created_at = slot·400/1000. 2500 slots → 1000 s.
        assert_eq!(slot_to_created_at(2_500), Some(1_000));
        assert_eq!(slot_to_created_at(0), Some(0));
        // A slot below the anchor underflows to None (rather than panicking).
        // (With GENESIS_SLOT == 0 nothing is below it; assert the arithmetic is
        //  overflow-safe at the extreme instead.)
        assert_eq!(slot_to_created_at(u64::MAX), None); // slot·SLOT_MS overflows
    }

    #[test]
    fn verdict_params_satisfy_the_logic_bounds() {
        // Deploy-time invariant (spec §Валидация): approval_threshold ∈ [5000,10000),
        // quorum_weight ≥ MIN_VOTE_WEIGHT, fee_bps < 10000. Route the baked consts
        // through runtime locals so this is a real check, not a const assertion.
        let scale = u16::try_from(conditional_funding_logic::APPROVAL_THRESHOLD_SCALE).unwrap();
        let (threshold, quorum, fee) = (
            std::hint::black_box(APPROVAL_THRESHOLD),
            std::hint::black_box(QUORUM_WEIGHT),
            std::hint::black_box(FEE_BPS),
        );
        assert!(threshold >= MIN_APPROVAL_THRESHOLD && threshold < scale);
        assert!(quorum >= MIN_VOTE_WEIGHT);
        assert!(fee < scale);
    }
}
