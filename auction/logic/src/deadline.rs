//! The deadline rule (auction spec §Правило дедлайна): an entry's escrow
//! `deadline` must leave room for the whole auction lifecycle —
//! `created_at + duration + DEADLINE_MARGIN`. The lifecycle ends at the close
//! (`created_at + duration`), so the margin is what a claimer actually has to
//! present the verdict on-chain before `refund()` opens.
//! All additions are `checked`; overflow is an error (never a skipped check);
//! the boundary is inclusive (exactly the minimum passes).

use crate::DEADLINE_MARGIN;

/// The earliest acceptable escrow `deadline` (unix seconds) for an entry born at
/// `created_at`, or `None` on time overflow / an unrepresentable `i64` instant.
pub fn min_deadline(created_at: u64, duration: u64) -> Option<i64> {
    let secs = created_at
        .checked_add(duration)?
        .checked_add(DEADLINE_MARGIN)?;
    i64::try_from(secs).ok()
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic, not the hot path
mod tests {
    use super::*;

    const CREATED: u64 = 1_000;
    const DUR: u64 = 600;

    #[test]
    fn min_deadline_is_the_exact_lower_bound() {
        // The inclusive `deadline >= min` gate itself lives in `validate::validate_entry`
        // (tested there); here we pin the bound value and its overflow behavior.
        assert_eq!(
            min_deadline(CREATED, DUR),
            Some((CREATED + DUR) as i64 + DEADLINE_MARGIN as i64)
        );
    }

    #[test]
    fn overflow_yields_none() {
        assert_eq!(min_deadline(u64::MAX, 1), None);
    }
}
