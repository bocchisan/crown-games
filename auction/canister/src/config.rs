//! Baked network config (`build.rs` from `../config/<profile>.toml`). Principals
//! are text (parsed at `init`); addresses are `[u8; 32]`. Nothing network in code.

include!(concat!(env!("OUT_DIR"), "/config.rs"));

/// Convert a Solana birth `slot` to `created_at` (unix seconds) by the pinned
/// linear anchor (spec §Состояния: "slot→time by a pinned SLOTS_PER_SECOND, as in
/// conditional-funding"; `SLOT_MS = 1000 / SLOTS_PER_SECOND`). Isolated here so
/// the one delicate time mapping has a single home. Checked; `None` if the slot
/// precedes the anchor or the arithmetic overflows. The anchor is a per-cluster
/// network constant — a placeholder until A5(devnet)/P8(mainnet).
pub fn slot_to_created_at(slot: u64) -> Option<u64> {
    let elapsed_slots = slot.checked_sub(GENESIS_SLOT)?;
    let elapsed_ms = elapsed_slots.checked_mul(SLOT_MS)?;
    GENESIS_UNIX.checked_add(elapsed_ms / 1_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_logic::{MAX_DURATION, MIN_DURATION};

    #[test]
    fn testnet_values_are_baked() {
        assert_eq!(PROFILE, "testnet");
        assert_eq!(CROWN_INDEX, "aaaaa-aa");
        assert_eq!(THRESHOLD_KEY, "dfx_test_key");
        assert_eq!(VOTING_PERIOD, 120);
        assert_eq!(PERFORM_WINDOW, 120);
        assert_eq!(MIN_ENTRY, 0);
        assert_eq!(SIGN_PRICE, 26_200_000_000);
        assert_eq!(FEE_BPS, 300);
        assert_eq!(CHAIN_ID, "devnet");
        assert_eq!(DOMAIN, "crown:two-outcome:devnet");
        assert_eq!(SLOT_MS, 400);
        assert_eq!(FEE_WALLET, [0u8; 32]);
        assert_eq!(FACTORY, [0u8; 32]);
        assert_eq!(GENESIS_SLOT, 0);
        assert_eq!(GENESIS_UNIX, 0);
    }

    #[test]
    fn timings_are_within_the_logic_bounds() {
        // Deploy invariant: voting_period/perform_window ∈ [MIN_DURATION, MAX_DURATION].
        let (vp, pw) = (
            std::hint::black_box(VOTING_PERIOD),
            std::hint::black_box(PERFORM_WINDOW),
        );
        let range = MIN_DURATION..=MAX_DURATION;
        assert!(range.contains(&vp));
        assert!(range.contains(&pw));
    }

    #[test]
    fn slot_to_created_at_is_linear_and_checked() {
        assert_eq!(slot_to_created_at(2_500), Some(1_000)); // 2500·400/1000
        assert_eq!(slot_to_created_at(0), Some(0));
        assert_eq!(slot_to_created_at(u64::MAX), None); // slot·SLOT_MS overflows
    }
}
