//! The deadline rule (auction spec §Правило дедлайна): an entry's escrow
//! `deadline` must leave room for the whole auction lifecycle —
//! `created_at + duration + perform_window + voting_period + DEADLINE_MARGIN`.
//! All additions are `checked`; overflow is an error (never a skipped check);
//! the boundary is inclusive (exactly the minimum passes).

use crate::DEADLINE_MARGIN;

/// The earliest acceptable escrow `deadline` (unix seconds) for an entry born at
/// `created_at`, or `None` on time overflow / an unrepresentable `i64` instant.
pub fn min_deadline(
    created_at: u64,
    duration: u64,
    perform_window: u64,
    voting_period: u64,
) -> Option<i64> {
    let secs = created_at
        .checked_add(duration)?
        .checked_add(perform_window)?
        .checked_add(voting_period)?
        .checked_add(DEADLINE_MARGIN)?;
    i64::try_from(secs).ok()
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic, not the hot path
mod tests {
    use super::*;

    const CREATED: u64 = 1_000;
    const DUR: u64 = 600;
    const PW: u64 = 300;
    const VP: u64 = 120;

    fn min() -> i64 {
        (CREATED + DUR + PW + VP) as i64 + DEADLINE_MARGIN as i64
    }

    #[test]
    fn min_deadline_is_the_exact_lower_bound() {
        // The inclusive `deadline >= min` gate itself lives in `validate::validate_entry`
        // (tested there); here we pin the bound value and its overflow behavior.
        assert_eq!(min_deadline(CREATED, DUR, PW, VP), Some(min()));
    }

    #[test]
    fn overflow_yields_none() {
        assert_eq!(min_deadline(u64::MAX, 1, 0, 0), None);
    }
}
