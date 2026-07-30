//! Reading `config/<profile>.toml` from a game's `build.rs` — the parsing half of
//! the bake, so the three games hold one copy instead of three.
//!
//! Deliberately not a TOML crate: the profiles are flat `key = value` files, and
//! a build-dependency on a parser would be more machinery than the thing it
//! parses. What matters is that the *reading* is identical across games — a
//! subtle difference in how a trailing `# comment` or a `_` separator is handled
//! would show up as a config value silently differing between two games baked
//! from the same file.
//!
//! Used from `build.rs` only. Each game still decides **which** keys it bakes and
//! what they mean; that is the part that is genuinely per-game.

/// The raw value token of `key = <token>`: the text before any trailing `#`
/// comment, trimmed, with one layer of quotes removed. Panics if the key is
/// absent — a missing config key must fail the build, not default.
pub fn str_of(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| {
            let rest = l.trim().strip_prefix(key)?.trim_start().strip_prefix('=')?;
            let rest = rest.split('#').next().unwrap_or(rest).trim();
            Some(rest.trim_matches('"').to_string())
        })
        .unwrap_or_else(|| panic!("missing `{key}` in config"))
}

/// A `u128` value, tolerating `_` digit separators.
pub fn u128_of(text: &str, key: &str) -> u128 {
    let raw = str_of(text, key);
    raw.replace('_', "")
        .parse()
        .unwrap_or_else(|_| panic!("`{key}` = `{raw}` is not an integer"))
}

/// Base58-decode a Solana address to `[u8; 32]`.
///
/// `strict` is the frozen (`mainnet`) profile: there a placeholder is a hard
/// error, because an address baked as zero matches nothing and would fail every
/// proof at runtime with no signal saying why. Off the frozen profile a
/// placeholder decodes to zero and warns — that is what lets a repo be checked
/// out and built before its addresses exist.
pub fn addr(s: &str, what: &str, strict: bool, game: &str) -> [u8; 32] {
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
            println!("cargo:warning={game}: `{what}` is a placeholder (`{s}`) — baked as unset");
            [0u8; 32]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "\
crown_index = \"aaaaa-aa\"   # a trailing comment
min_gross   = 1_860_000
fee_bps     = 300
";

    #[test]
    fn a_value_survives_quotes_comments_and_separators() {
        assert_eq!(str_of(CFG, "crown_index"), "aaaaa-aa");
        assert_eq!(u128_of(CFG, "min_gross"), 1_860_000);
        assert_eq!(u128_of(CFG, "fee_bps"), 300);
    }

    #[test]
    #[should_panic(expected = "missing `absent` in config")]
    fn a_missing_key_fails_the_build_rather_than_defaulting() {
        str_of(CFG, "absent");
    }

    #[test]
    fn a_placeholder_is_zero_off_the_frozen_profile_and_fatal_on_it() {
        assert_eq!(addr("PLACEHOLDER_x", "factory", false, "t"), [0u8; 32]);
        let real = bs58::encode([7u8; 32]).into_string();
        assert_eq!(addr(&real, "factory", true, "t"), [7u8; 32]);
    }

    #[test]
    #[should_panic(expected = "mainnet requires real addresses")]
    fn a_placeholder_on_the_frozen_profile_does_not_compile() {
        addr("PLACEHOLDER_x", "factory", true, "t");
    }
}
