//! Bakes the active config profile (`../config/<profile>.toml`) into the wasm.
//! Nothing network lives in code: the index principal, threshold key name, the
//! verdict params (voting period, approval threshold, quorum weight), the paid-
//! pull price, fee, chain id, factory, and verdict domain all come from
//! `config/`. Solana addresses (`fee_wallet`, `factory`) are base58-decoded to
//! `[u8; 32]`; a placeholder decodes to zero (a hard error on the frozen
//! `mainnet` profile). `min_gross` is the per-contribution floor: the signature
//! amortizes across `N` donors, but the worst case is `N = 1`, so the floor is
//! what keeps a one-contribution collection non-negative (`cost.md §5,§6`).

use crown_games_common::config_bake::{addr as decode_addr, str_of, u128_of};
use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(crown_profile, values(\"testnet\", \"mainnet\"))");
    let profile = env::var("CROWN_PROFILE").unwrap_or_else(|_| "testnet".to_string());
    println!("cargo:rustc-cfg=crown_profile=\"{profile}\"");
    println!("cargo:rerun-if-env-changed=CROWN_PROFILE");

    // config/ sits at the game root; the canister crate is one level down.
    let cfg_path = format!("../config/{profile}.toml");
    println!("cargo:rerun-if-changed={cfg_path}");
    let text = fs::read_to_string(&cfg_path).unwrap_or_else(|_| panic!("missing {cfg_path}"));
    let strict = profile == "mainnet";

    let index = str_of(&text, "crown_index");
    let threshold_key = str_of(&text, "threshold_key");
    let voting_period = u128_of(&text, "voting_period") as u64;
    let approval_threshold = u16::try_from(u128_of(&text, "approval_threshold"))
        .unwrap_or_else(|_| panic!("`approval_threshold` out of u16 range"));
    let quorum_weight = u128_of(&text, "quorum_weight");
    let min_gross = u128_of(&text, "min_gross") as u64;
    let sign_price = u128_of(&text, "sign_price");
    let root_price = u128_of(&text, "root_price");
    // slot→time anchor (spec §Тайминги: "slot→time by a pinned SLOTS_PER_SECOND").
    // `slot_ms = 1000 / SLOTS_PER_SECOND`. The genesis anchor is a per-cluster
    // network fact: measured on devnet at F5, still a placeholder (0) on mainnet
    // until P8 — where a zero `genesis_unix` is a hard error rather than a quiet
    // decade-long offset.
    let slot_ms = u128_of(&text, "slot_ms") as u64;
    let genesis_slot = u128_of(&text, "genesis_slot") as u64;
    let genesis_unix = u128_of(&text, "genesis_unix") as u64;
    if strict && genesis_unix == 0 {
        panic!("`genesis_unix` = 0 (mainnet requires a real slot→time anchor)");
    }
    let fee_bps = u16::try_from(u128_of(&text, "fee_bps"))
        .unwrap_or_else(|_| panic!("`fee_bps` out of u16 range"));
    let fee_wallet = decode_addr(
        &str_of(&text, "fee_wallet"),
        "fee_wallet",
        strict,
        "conditional-funding",
    );
    let chain_id = str_of(&text, "id");
    let factory = decode_addr(
        &str_of(&text, "factory"),
        "factory",
        strict,
        "conditional-funding",
    );
    let domain = str_of(&text, "domain");

    let out = format!(
        "// Baked from {cfg_path} — do not edit. Nothing network lives in code.\n\
         pub const PROFILE: &str = {profile:?};\n\
         /// Principal of crown-indexer (parsed at `init`; used to key birth proofs).\n\
         pub const CROWN_INDEX: &str = {index:?};\n\
         /// Threshold Ed25519 key name for the per-scope resolver.\n\
         pub const THRESHOLD_KEY: &str = {threshold_key:?};\n\
         /// Voting-window length (seconds), baked into every `collection_id`.\n\
         pub const VOTING_PERIOD: u64 = {voting_period};\n\
         /// Approval threshold (ten-thousandths), baked into every `collection_id`.\n\
         pub const APPROVAL_THRESHOLD: u16 = {approval_threshold};\n\
         /// Quorum weight (reputation minor units), baked into every `collection_id`.\n\
         pub const QUORUM_WEIGHT: u128 = {quorum_weight};\n\
         /// Per-contribution floor (cost.md §5,§6); worst case is `N = 1`.\n\
         pub const MIN_GROSS: u64 = {min_gross};\n\
         /// Price charged for a verdict signature (<= relay SIGN_PRICE).\n\
         pub const SIGN_PRICE: u128 = {sign_price};\n\
         /// Price charged for a certified-root refresh (covers the BLS pairings).\n\
         pub const ROOT_PRICE: u128 = {root_price};\n\
         pub const FEE_BPS: u16 = {fee_bps};\n\
         /// Fee wallet (Solana address). Zero if a placeholder.\n\
         pub const FEE_WALLET: [u8; 32] = {fee_wallet:?};\n\
         /// Cluster id string (the `chain:` field of signed messages).\n\
         pub const CHAIN_ID: &str = {chain_id:?};\n\
         /// Pinned two-outcome factory (Solana address). Zero if a placeholder.\n\
         pub const FACTORY: [u8; 32] = {factory:?};\n\
         /// Verdict domain of the form (`crown:two-outcome:<cluster>`).\n\
         pub const DOMAIN: &str = {domain:?};\n\
         /// Milliseconds per Solana slot (`1000 / SLOTS_PER_SECOND`).\n\
         pub const SLOT_MS: u64 = {slot_ms};\n\
         /// Anchor slot for slot→time. Measured on devnet (F5); mainnet pinned at P8.\n\
         pub const GENESIS_SLOT: u64 = {genesis_slot};\n\
         /// Anchor unix time (seconds) for slot→time. Measured on devnet (F5).\n\
         pub const GENESIS_UNIX: u64 = {genesis_unix};\n",
    );
    let dst = Path::new(&env::var("OUT_DIR").unwrap()).join("config.rs");
    fs::write(&dst, out).unwrap();
}
