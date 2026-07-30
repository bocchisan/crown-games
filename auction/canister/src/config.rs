//! Baked network config (`build.rs` from `../config/<profile>.toml`). Principals
//! are text (parsed at `init`); addresses are `[u8; 32]`. Nothing network in code.

include!(concat!(env!("OUT_DIR"), "/config.rs"));

/// Convert a Solana birth `slot` to `created_at` (unix seconds) by the pinned
/// linear anchor (spec §Состояния: "slot→time by a pinned SLOTS_PER_SECOND, as in
/// conditional-funding"; `SLOT_MS = 1000 / SLOTS_PER_SECOND`). Isolated here so
/// the one delicate time mapping has a single home. Checked; `None` if the slot
/// precedes the anchor or the arithmetic overflows. The anchor is a per-cluster
/// network constant: measured on devnet at A5, still a placeholder on mainnet
/// until P8 (where `build.rs` refuses to compile a zero one).
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
        assert_eq!(THRESHOLD_KEY, "key_1");
        assert_eq!(VOTING_PERIOD, 120);
        assert_eq!(PERFORM_WINDOW, 120);
        assert_eq!(MIN_ENTRY, 250_000);
        assert_eq!(SIGN_PRICE, 26_200_000_000);
        assert_eq!(ROOT_PRICE, 1_000_000_000);
        assert_eq!(FEE_BPS, 300);
        assert_eq!(CHAIN_ID, "devnet");
        assert_eq!(DOMAIN, "crown:two-outcome:devnet");
        assert_eq!(SLOT_MS, 400);
        // fee_wallet / factory are the **real** devnet addresses: the escrow
        // address commits both (harness §9), so a placeholder here derives
        // addresses no birth can ever live at — and the refusal reads as a bad
        // proof rather than a bad config. Pinned by the live runs (T5/A5/F5).
        assert_eq!(
            FEE_WALLET,
            b58("FS6ZNuPxXqWSGzwXEQpfoxikDksbEzmrXGZDFXmFj6vS")
        );
        assert_eq!(FACTORY, b58("BGVQrwSwkFQspL69DjGBFgKSgL6rutPqgcgEskmi8A4y"));
        // The slot→time anchor is a measured devnet fact (A5), not a deploy
        // secret: a zero anchor maps every real slot to 1975, so the bidding
        // window is shut before the first registration and the refusal reads as
        // groundless. Pinned here so a config edit that drops it fails a test.
        assert_eq!(GENESIS_SLOT, 479_731_554);
        assert_eq!(GENESIS_UNIX, 1_785_326_212);
    }

    // **Нет теста «игровой флор ≥ индексного», и это решение.** Он существовал и
    // сравнивал `MIN_GROSS` с литералом `200_000`, вписанным рядом, — то есть с
    // копией индексного флора, живущей в этом же файле. Покраснеть при том
    // событии, ради которого он написан (индекс поднял свой флор), он не мог
    // физически: литерал в чужом репе не двигается. Сделать его настоящим —
    // значит завести build-зависимость на конфиг `crown-indexer`, а репы
    // независимы by design (`repo-map.md`). Инвариант никуда не делся, но живёт
    // там, где его можно проверить: шагом cost-gate в `07-build-plan.md §P8`,
    // где оба числа перемеряются разом. Правило проекта — проверка, не способная
    // покраснеть, хуже отсутствующей (`P7.5`, `P7.13`).

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
        // The fixed point is what makes the anchor an anchor: `SLOT_MS` is only
        // the slope, and a slope alone never ties the model to the network.
        assert_eq!(slot_to_created_at(GENESIS_SLOT), Some(GENESIS_UNIX));
        // Linear in the offset: 2500 slots · 400 ms = 1000 s.
        assert_eq!(
            slot_to_created_at(GENESIS_SLOT + 2_500),
            Some(GENESIS_UNIX + 1_000)
        );
        // Below the anchor the model has nothing to say — `None`, never a wrap.
        assert_eq!(slot_to_created_at(GENESIS_SLOT - 1), None);
        assert_eq!(slot_to_created_at(u64::MAX), None); // slot·SLOT_MS overflows
    }

    /// base58 → 32 bytes, for pinning the baked addresses above.
    fn b58(s: &str) -> [u8; 32] {
        bs58::decode(s).into_vec().unwrap().try_into().unwrap()
    }
}
