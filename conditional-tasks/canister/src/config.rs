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
        assert_eq!(THRESHOLD_KEY, "key_1");
        assert_eq!(VOTING_PERIOD, 120);
        assert_eq!(MIN_GROSS, 1_860_000);
        assert_eq!(SIGN_PRICE, 26_200_000_000);
        assert_eq!(ROOT_PRICE, 1_000_000_000);
        assert_eq!(FEE_BPS, 300);
        assert_eq!(CHAIN_ID, "devnet");
        assert_eq!(DOMAIN, "crown:two-outcome:devnet");
        // fee_wallet / factory are the **real** devnet addresses: the escrow
        // address commits both (harness §9), so a placeholder here derives
        // addresses no birth can ever live at — and the refusal reads as a bad
        // proof rather than a bad config. Pinned by the live runs (T5/A5/F5).
        assert_eq!(
            FEE_WALLET,
            b58("FS6ZNuPxXqWSGzwXEQpfoxikDksbEzmrXGZDFXmFj6vS")
        );
        assert_eq!(FACTORY, b58("BGVQrwSwkFQspL69DjGBFgKSgL6rutPqgcgEskmi8A4y"));
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
