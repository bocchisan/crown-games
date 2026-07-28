//! Bakes the active config profile (`../config/<profile>.toml`) into the wasm.
//! Nothing network lives in code: the index principal, threshold key name,
//! timings/floor/fee, chain id, factory, and verdict domain all come from
//! `config/`. Solana addresses (`fee_wallet`, `factory`) are base58-decoded to
//! `[u8; 32]`; a placeholder decodes to zero (a hard error on the frozen
//! `mainnet` profile).

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
    let voting_period = u128_of(&text, "voting_period") as i64;
    let min_gross = u128_of(&text, "min_gross") as u64;
    let sign_price = u128_of(&text, "sign_price");
    let fee_bps = u128_of(&text, "fee_bps") as u16;
    let fee_wallet = addr(&str_of(&text, "fee_wallet"), "fee_wallet", strict);
    let chain_id = str_of(&text, "id");
    let factory = addr(&str_of(&text, "factory"), "factory", strict);
    let domain = str_of(&text, "domain");

    let out = format!(
        "// Baked from {cfg_path} — do not edit. Nothing network lives in code.\n\
         pub const PROFILE: &str = {profile:?};\n\
         /// Principal of crown-indexer (parsed at `init`; used to key birth proofs).\n\
         pub const CROWN_INDEX: &str = {index:?};\n\
         /// Threshold Ed25519 key name for the per-scope resolver.\n\
         pub const THRESHOLD_KEY: &str = {threshold_key:?};\n\
         /// Voting-window length (seconds), baked into every `task_id`.\n\
         pub const VOTING_PERIOD: i64 = {voting_period};\n\
         /// Game acceptance floor (>= index MIN_GROSS).\n\
         pub const MIN_GROSS: u64 = {min_gross};\n\
         /// Price charged for a verdict signature (<= relay SIGN_PRICE).\n\
         pub const SIGN_PRICE: u128 = {sign_price};\n\
         pub const FEE_BPS: u16 = {fee_bps};\n\
         /// Fee wallet (Solana address). Zero if a placeholder.\n\
         pub const FEE_WALLET: [u8; 32] = {fee_wallet:?};\n\
         /// Cluster id string (the `chain:` field of signed messages).\n\
         pub const CHAIN_ID: &str = {chain_id:?};\n\
         /// Pinned two-outcome factory (Solana address). Zero if a placeholder.\n\
         pub const FACTORY: [u8; 32] = {factory:?};\n\
         /// Verdict domain of the form (`crown:two-outcome:<cluster>`).\n\
         pub const DOMAIN: &str = {domain:?};\n",
    );
    let dst = Path::new(&env::var("OUT_DIR").unwrap()).join("config.rs");
    fs::write(&dst, out).unwrap();
}

fn str_of(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| {
            let rest = l.trim().strip_prefix(key)?.trim_start().strip_prefix('=')?;
            let rest = rest.split('#').next().unwrap_or(rest).trim();
            Some(rest.trim_matches('"').to_string())
        })
        .unwrap_or_else(|| panic!("missing `{key}` in config"))
}

fn u128_of(text: &str, key: &str) -> u128 {
    let raw = str_of(text, key);
    raw.replace('_', "")
        .parse()
        .unwrap_or_else(|_| panic!("`{key}` = `{raw}` is not an integer"))
}

/// Base58-decode an address; a placeholder → zero (a hard error on mainnet).
fn addr(s: &str, what: &str, strict: bool) -> [u8; 32] {
    match bs58::decode(s).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        }
        _ => {
            if strict {
                panic!("`{what}` = `{s}` is not a valid address (mainnet requires real addresses)");
            }
            println!("cargo:warning=conditional-tasks: `{what}` is a placeholder (`{s}`) — baked as unset");
            [0u8; 32]
        }
    }
}
