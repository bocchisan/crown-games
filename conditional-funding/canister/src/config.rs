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
/// `GENESIS_UNIX`) is a per-cluster network constant: measured on devnet at F5,
/// still a placeholder on mainnet until P8 (where `build.rs` refuses to compile a
/// zero one).
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
        assert_eq!(THRESHOLD_KEY, "key_1");
        assert_eq!(VOTING_PERIOD, 120);
        assert_eq!(APPROVAL_THRESHOLD, 5_000);
        assert_eq!(QUORUM_WEIGHT, 150_000);
        assert_eq!(MIN_GROSS, 250_000);
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
        // The slot→time anchor is not: it is a measured devnet fact (F5). A zero
        // anchor maps every real slot to 1975, so the funding window is shut
        // before the first materialization and the refusal reads as groundless.
        assert_eq!(GENESIS_SLOT, 479_731_554);
        assert_eq!(GENESIS_UNIX, 1_785_326_212);
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

    /// base58 → 32 bytes, for pinning the baked addresses above.
    fn b58(s: &str) -> [u8; 32] {
        bs58::decode(s).into_vec().unwrap().try_into().unwrap()
    }
}
