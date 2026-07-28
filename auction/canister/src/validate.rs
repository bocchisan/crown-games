//! Registration validation (auction spec §Таблица переходов `register_entry`,
//! §Правило дедлайна, §create_auction footnote¹). Per-entry gates (`gross ≥
//! min_entry`, the deadline margin) apply on every `register_entry`; the rule-
//! snapshot range checks (`duration`/`perform_window`/`voting_period` ∈
//! `[MIN_DURATION, MAX_DURATION]`) apply once, at materialization. Pure, ordered,
//! `checked` — an unrepresentable instant is `TimeOverflow`, not a panic.

use auction_logic::{min_deadline, MAX_DURATION, MIN_DURATION};

/// Registration refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegError {
    GrossBelowMinEntry,
    DurationOutOfRange,
    PerformWindowOutOfRange,
    VotingPeriodOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
}

/// Per-entry gate (every `register_entry`): `gross ≥ min_entry`, then the escrow
/// `deadline` leaves room for the whole lifecycle (spec §Правило дедлайна).
pub fn validate_entry(
    gross: u64,
    min_entry: u64,
    deadline: i64,
    created_at: u64,
    duration: u64,
    perform_window: u64,
    voting_period: u64,
) -> Result<(), RegError> {
    if gross < min_entry {
        return Err(RegError::GrossBelowMinEntry);
    }
    match min_deadline(created_at, duration, perform_window, voting_period) {
        None => Err(RegError::TimeOverflow),
        Some(min) if deadline < min => Err(RegError::DeadlineTooTight),
        Some(_) => Ok(()),
    }
}

/// Materialization gate (first confirmed entry): the rule snapshot ranges
/// (spec §create_auction footnote¹). Checked in a fixed order.
pub fn validate_ranges(
    duration: u64,
    perform_window: u64,
    voting_period: u64,
) -> Result<(), RegError> {
    let range = MIN_DURATION..=MAX_DURATION;
    if !range.contains(&duration) {
        return Err(RegError::DurationOutOfRange);
    }
    if !range.contains(&perform_window) {
        return Err(RegError::PerformWindowOutOfRange);
    }
    if !range.contains(&voting_period) {
        return Err(RegError::VotingPeriodOutOfRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_logic::DEADLINE_MARGIN;

    const CREATED: u64 = 1_000;
    const DUR: u64 = 600;
    const PW: u64 = 300;
    const VP: u64 = 120;

    fn tight() -> i64 {
        // created + dur + pw + vp + margin
        i64::try_from(CREATED + DUR + PW + VP + DEADLINE_MARGIN).unwrap()
    }

    #[test]
    fn gross_below_min_entry_is_rejected_first() {
        assert_eq!(
            validate_entry(99, 100, tight(), CREATED, DUR, PW, VP),
            Err(RegError::GrossBelowMinEntry)
        );
        // At/above min_entry with a tight deadline → ok.
        assert_eq!(
            validate_entry(100, 100, tight(), CREATED, DUR, PW, VP),
            Ok(())
        );
    }

    #[test]
    fn deadline_boundary_is_inclusive_and_overflow_is_reported() {
        assert_eq!(validate_entry(0, 0, tight(), CREATED, DUR, PW, VP), Ok(()));
        assert_eq!(
            validate_entry(0, 0, tight() - 1, CREATED, DUR, PW, VP),
            Err(RegError::DeadlineTooTight)
        );
        assert_eq!(
            validate_entry(0, 0, i64::MAX, u64::MAX, 1, 0, 0),
            Err(RegError::TimeOverflow)
        );
    }

    #[test]
    fn ranges_checked_in_order() {
        assert_eq!(validate_ranges(DUR, PW, VP), Ok(()));
        assert_eq!(
            validate_ranges(MIN_DURATION - 1, PW, VP),
            Err(RegError::DurationOutOfRange)
        );
        assert_eq!(
            validate_ranges(DUR, MAX_DURATION + 1, VP),
            Err(RegError::PerformWindowOutOfRange)
        );
        assert_eq!(
            validate_ranges(DUR, PW, MIN_DURATION - 1),
            Err(RegError::VotingPeriodOutOfRange)
        );
        // Bounds inclusive.
        assert_eq!(
            validate_ranges(MIN_DURATION, MAX_DURATION, MIN_DURATION),
            Ok(())
        );
    }
}
