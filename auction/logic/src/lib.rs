#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
//! auction logic — state machine, vote tally, three-stage resolution, deadline
//! rule (zero-dep). On the `two-outcome` form: the winner lot's votes settle or
//! cancel it; each contribution is signed independently (`resolver = key([entry_id])`).
//! The winner is named by the recipient (`pick_winner`), not computed on-chain.

pub mod deadline;
pub mod machine;
pub mod verdict;

pub use deadline::min_deadline;
pub use machine::{
    resolve, step, Action, Auction, Known, Outcome, Resolution, State, StepError, Vote,
};
pub use verdict::verdict;

/// Version of the rules (first version by the current spec; pinned by a test).
pub const LOGIC_VERSION: u32 = 1;

/// Minimum vote weight (reputation minor units).
pub const MIN_VOTE_WEIGHT: u128 = 100_000;

/// Duration bounds (seconds); also the range for `perform_window`/`voting_period`.
pub const MIN_DURATION: u64 = 60; // 1 min
pub const MAX_DURATION: u64 = 2_592_000; // 30 days

/// Donor-UI safety margin (seconds): 72h.
pub const DEADLINE_MARGIN: u64 = 259_200;

#[cfg(test)]
mod version_lock {
    #[test]
    fn logic_version_is_pinned() {
        // The rules are versioned by this constant; a deliberate change must
        // update it (harness §7: a new version is a fresh canister).
        assert_eq!(super::LOGIC_VERSION, 1);
    }
}
