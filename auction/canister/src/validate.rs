//! Registration validation (auction spec §Таблица переходов `register_entry`,
//! §Правило дедлайна, §get_auction_id footnote¹). Per-entry gates (`gross ≥
//! min_entry`, the deadline margin) apply on every `register_entry`; the rule-
//! snapshot range check (`duration ∈ [MIN_DURATION, MAX_DURATION]`) applies once,
//! at materialization. Pure, ordered, `checked` — an unrepresentable instant is
//! `TimeOverflow`, not a panic.

use auction_logic::{min_deadline, MAX_DURATION, MIN_DURATION};

/// Registration refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegError {
    GrossBelowMinEntry,
    DurationOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
}

/// The floor actually enforced on an entry: the auction's own `min_entry` may
/// only **raise** the platform floor, never lower it.
///
/// `min_entry` is a preimage field its creator picks, and the resolver here is
/// per-entry (`key([entry_id])`) — every contribution buys its own signature,
/// with nothing to amortize it against. A creator who set `min_entry = 0` would
/// otherwise hand the platform a full unamortized signature per dust entry
/// (`cost.md §6`; same reasoning as the fee coming from config, harness §9: the
/// price list is the game's, not the caller's).
pub fn entry_floor(min_entry: u64, platform_floor: u64) -> u64 {
    min_entry.max(platform_floor)
}

/// Per-entry gate (every `register_entry`): `gross ≥ floor` ([`entry_floor`]),
/// then the escrow `deadline` leaves room for the whole lifecycle (spec §Правило
/// дедлайна).
pub fn validate_entry(
    gross: u64,
    floor: u64,
    deadline: i64,
    created_at: u64,
    duration: u64,
) -> Result<(), RegError> {
    if gross < floor {
        return Err(RegError::GrossBelowMinEntry);
    }
    match min_deadline(created_at, duration) {
        None => Err(RegError::TimeOverflow),
        Some(min) if deadline < min => Err(RegError::DeadlineTooTight),
        Some(_) => Ok(()),
    }
}

/// Materialization gate (first confirmed entry): the rule snapshot range
/// (spec §get_auction_id footnote¹).
pub fn validate_ranges(duration: u64) -> Result<(), RegError> {
    if !(MIN_DURATION..=MAX_DURATION).contains(&duration) {
        return Err(RegError::DurationOutOfRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_logic::DEADLINE_MARGIN;

    const CREATED: u64 = 1_000;
    const DUR: u64 = 600;

    fn tight() -> i64 {
        // created + dur + margin
        i64::try_from(CREATED + DUR + DEADLINE_MARGIN).unwrap()
    }

    #[test]
    fn gross_below_min_entry_is_rejected_first() {
        assert_eq!(
            validate_entry(99, 100, tight(), CREATED, DUR),
            Err(RegError::GrossBelowMinEntry)
        );
        // At/above min_entry with a tight deadline → ok.
        assert_eq!(validate_entry(100, 100, tight(), CREATED, DUR), Ok(()));
    }

    #[test]
    fn the_auction_may_raise_the_platform_floor_but_never_lower_it() {
        // A creator-chosen `min_entry` under the platform floor does not open the
        // door: the floor is the game's price list, not the caller's.
        assert_eq!(entry_floor(0, 1_000), 1_000);
        assert_eq!(entry_floor(500, 1_000), 1_000);
        // Raising above the platform floor is the creator's to do.
        assert_eq!(entry_floor(5_000, 1_000), 5_000);
        // And the gate enforces exactly that floor.
        assert_eq!(
            validate_entry(500, entry_floor(0, 1_000), tight(), CREATED, DUR),
            Err(RegError::GrossBelowMinEntry)
        );
        assert_eq!(
            validate_entry(1_000, entry_floor(0, 1_000), tight(), CREATED, DUR),
            Ok(())
        );
    }

    #[test]
    fn deadline_boundary_is_inclusive_and_overflow_is_reported() {
        assert_eq!(validate_entry(0, 0, tight(), CREATED, DUR), Ok(()));
        assert_eq!(
            validate_entry(0, 0, tight() - 1, CREATED, DUR),
            Err(RegError::DeadlineTooTight)
        );
        assert_eq!(
            validate_entry(0, 0, i64::MAX, u64::MAX, 1),
            Err(RegError::TimeOverflow)
        );
    }

    #[test]
    fn duration_range_is_inclusive() {
        assert_eq!(validate_ranges(DUR), Ok(()));
        assert_eq!(
            validate_ranges(MIN_DURATION - 1),
            Err(RegError::DurationOutOfRange)
        );
        assert_eq!(
            validate_ranges(MAX_DURATION + 1),
            Err(RegError::DurationOutOfRange)
        );
        assert_eq!(validate_ranges(MIN_DURATION), Ok(()));
        assert_eq!(validate_ranges(MAX_DURATION), Ok(()));
    }
}
