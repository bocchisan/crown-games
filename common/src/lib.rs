#![forbid(unsafe_code)]
//! `crown-games-common` — the delicate, game-agnostic crypto shared by every
//! class-B game canister on the `two-outcome` form:
//!
//! - [`birth`]   — the index birth/reputation proof: BLS certificate verification
//!   (one delegation level, against the pinned NNS root key) + the hash-tree
//!   witness. This is the root of trust of a *blind* game (no RPC, no call to the
//!   index) and the single piece that must **never** be copy-pasted per game.
//! - [`resolver`] — threshold-Ed25519 resolver derivation (`key([scope_id])`),
//!   the IC's own derivation, done locally so `get_resolver` is a free `query`.
//! - [`address`]  — the `two-outcome` escrow-address PDA (`crown-salt` +
//!   `crown-derive`), so a predicted address matches the created escrow byte-for-byte.
//! - [`wallet`]   — the wallet-signature primitives: Ed25519 `verify_strict`,
//!   `bs58` fixed-array decode, and the frozen `verdict_message`.
//!
//! Game-specific parts (the `scope_id` preimage, the signed-message wording, the
//! request framing) live in each game canister; only the delicate shared crypto
//! lives here.

pub mod address;
pub mod birth;
pub mod request;
pub mod resolver;
pub mod wallet;

pub use birth::{birth_from_witness, certified_root, reputation_from_witness, Birth};
pub use request::{parse, Request};
pub use wallet::{bs58_array, verdict_message, verify};
