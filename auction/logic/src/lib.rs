#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
//! auction logic — state machine, three-stage resolution, deadline rule
//! (zero-dep). On the `two-outcome` form: the bidding window closes and the
//! heaviest eligible lot settles, every other contribution cancels; each
//! contribution is signed independently (`resolver = key([entry_id])`).
//! The winner is arithmetic — nobody votes on it and nobody picks it.

pub mod deadline;
pub mod machine;

pub use deadline::min_deadline;
pub use machine::{resolve, step, tick, Action, Auction, Known, Resolution, State, StepError};

/// Version of the rules (pinned by a test; a deliberate change must bump it).
pub const LOGIC_VERSION: u32 = 2;

/// Duration bounds (seconds) of the bidding window.
pub const MIN_DURATION: u64 = 60; // 1 min
pub const MAX_DURATION: u64 = 2_592_000; // 30 days

/// Donor-UI safety margin (seconds): 72h.
pub const DEADLINE_MARGIN: u64 = 259_200;

#[cfg(test)]
mod version_lock {
    #[test]
    fn logic_version_is_pinned() {
        // The rules are versioned by this constant; a deliberate change must
        // update it (harness §7: a new version is a fresh canister). Bumped to 2
        // when the vote and the recipient's `pick_winner` were replaced by the
        // arithmetic close (the heaviest eligible lot wins at `T`).
        assert_eq!(super::LOGIC_VERSION, 2);
    }
}
