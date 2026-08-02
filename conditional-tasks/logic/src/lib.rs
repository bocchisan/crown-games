#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
//! conditional-tasks logic — state machine + verdict rule (zero-dep). Carries
//! `LOGIC_VERSION`. Blind: no chain, no I/O; pure `f(votes, deadline, now)`.
//!
//! Windows are derived from the escrow `deadline` (spec §Тайминги), so the
//! canister needs neither a create-clock nor a timer.

pub mod machine;
pub mod verdict;

pub use machine::{step, Action, Outcome, State, StepError, Task, Vote};
pub use verdict::verdict;

/// Version of the rules — bumped only by a deliberate change to the machine or
/// verdict rule.
pub const LOGIC_VERSION: u32 = 5;

/// Minimum vote weight (reputation minor units); a lighter vote never counts.
pub const MIN_VOTE_WEIGHT: u128 = 100_000;

/// Duration bounds (seconds): a task's `duration ∈ [MIN_DURATION, MAX_DURATION]`.
pub const MIN_DURATION: i64 = 60; // 1 min
pub const MAX_DURATION: i64 = 2_592_000; // 30 days

/// Gap (seconds) the verdict window leaves below the escrow `deadline`, so the
/// verdict always lands before on-chain `refund()` opens (72h).
pub const DEADLINE_MARGIN: i64 = 259_200;
