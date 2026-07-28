#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
//! conditional-funding logic — collection state machine + verdict with quorum
//! (zero-dep). Generalizes tasks from one escrow to a set (`B=N`), all-or-
//! nothing. Blind, no registry: membership is derivation, not a list.
//!
//! P0 skeleton: types + version. The transition table and the quorum verdict
//! (quorum over both sides, strict majority, tie/undershoot/overflow → refund)
//! land at F1 with property tests.

pub mod machine;
pub mod verdict;

pub use machine::{step, Action, Collection, Outcome, State, StepError, Vote};
pub use verdict::verdict;

/// Version of the rules.
pub const LOGIC_VERSION: u32 = 3;

/// Minimum vote weight (reputation minor units).
pub const MIN_VOTE_WEIGHT: u128 = 100_000;

/// Lower bound of the approval threshold (ten-thousandths); `5_000` = strict
/// majority.
pub const MIN_APPROVAL_THRESHOLD: u16 = 5_000;

/// Denominator and exclusive upper bound of the approval threshold.
pub const APPROVAL_THRESHOLD_SCALE: u32 = 10_000;

/// Duration bounds (seconds) of the funding window.
pub const MIN_DURATION: u64 = 60; // 1 min
pub const MAX_DURATION: u64 = 7_776_000; // 90 days
