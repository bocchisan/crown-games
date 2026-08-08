#![forbid(unsafe_code)]
// The ban is a crate lint, not a habit — the same one `crown-reduce`, the index
// and each game's `logic/` already carry, and this crate had the weakest claim to
// being without it: it is the half that reads **hostile bytes**. Every public
// verifier here (`request::parse`, `field::hex_*`, `birth_from_witness`,
// `certified_root`) is handed attacker-chosen input on the anonymous boundary, so
// a panic is a denial of service and an unmarked overflow is a wrong weight. The
// behaviour was already right (`birth::malformed_bytes_never_panic` pins it); what
// was missing is the compiler refusing the next line that isn't. Tests are exempt —
// `unwrap` in a test *is* the assertion — and so is `config_bake`, which runs in
// `build.rs`, where a panic is a failed build rather than a wedged canister.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]
//! `crown-games-common` — the delicate, game-agnostic crypto shared by every
//! class-B game canister on the `two-outcome` form:
//!
//! - [`birth`]   — the index birth/reputation proof: BLS certificate verification
//!   (one delegation level, against the pinned NNS root key) + the hash-tree
//!   witness. This is the root of trust of a *blind* game (no RPC, no call to the
//!   index) and the single piece that must **never** be copy-pasted per game.
//! - [`roots`]    — the cache of authenticated index roots: the paid `push_root`
//!   runs the certificate's BLS pairings once, and every per-caller proof is a
//!   hash-tree walk against the cache. One mechanism for every game — the cost of
//!   the anonymous boundary must not differ per game (`games-harness.md §6`).
//! - [`resolver`] — threshold-Ed25519 resolver derivation (`key([scope_id])`),
//!   the IC's own derivation, done locally so `get_resolver` is a free `query`.
//! - [`address`]  — the `two-outcome` escrow-address PDA (`crown-salt` +
//!   `crown-derive`), so a predicted address matches the created escrow byte-for-byte.
//! - [`wallet`]   — the wallet-signature primitives: Ed25519 `verify_strict`,
//!   `bs58` fixed-array decode, and the frozen `verdict_message`.
//! - [`signing`]  — verdict-signature memoization (non-negativity invariant #5):
//!   a produced signature is served free, and the right to sign is claimed before
//!   the `await` so N concurrent callers cannot each buy the same bytes.
//! - [`field`]    — the book's `chain_id` derivation (it must equal the index's
//!   byte for byte) plus the ingress field decoders and the boundary constants.
//! - [`config_bake`] — reading `config/<profile>.toml` from a game's `build.rs`.
//!   Not runtime code; it is here so the three games read one file format one way.
//!
//! Game-specific parts (the `scope_id` preimage, the signed-message wording, the
//! request framing) live in each game canister; only the delicate shared crypto
//! lives here.

pub mod address;
pub mod birth;
pub mod config_bake;
pub mod field;
pub mod request;
pub mod resolver;
pub mod roots;
pub mod signing;
pub mod wallet;

pub use birth::{
    birth_from_witness, certified_root, reputation_from_witness, Birth, IC_MAINNET_ROOT_KEY,
};
pub use field::{chain_id, MAX_ARG_BYTES, V_MAX};
pub use request::{parse, Request};
pub use roots::ROOT_CACHE;
pub use signing::SignedVerdict;
pub use wallet::{bs58_array, verdict_message, verify};
