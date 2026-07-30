//! Registration validation (tasks spec §Валидация регистрации). A pure, ordered
//! sequence of refusals; the boundary is exact (the minimum passes, one second
//! under fails). Time arithmetic is `checked` — an unrepresentable instant is
//! `TimeOverflow`, not a panic.

use conditional_tasks_logic::{DEADLINE_MARGIN, MAX_DURATION, MIN_DURATION};

/// The registration inputs that gate acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegInputs {
    pub gross: u64,
    pub duration: i64,
    pub deadline: i64,
    pub voting_period: i64,
    pub now: i64,
}

/// Registration refusals, in the exact order they are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegError {
    GrossBelowFloor,
    DurationOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
}

/// Validate a registration against the game floor and the timeline, in the spec
/// order: floor → duration → deadline.
///
/// Every check here is a platform invariant, not a recipient preference. The
/// recipient's own terms (a minimum, a "not accepting", a reputation bar) are a
/// client-side filter and deliberately absent: this runs behind a birth proof,
/// so a refusal lands after the escrow is funded and paid for, where it costs
/// the donor and protects no one (`P7.14`; the remedy for an unwanted task is
/// `decline`, or the deadline's `refund()`).
pub fn validate_registration(game_floor: u64, inp: &RegInputs) -> Result<(), RegError> {
    if inp.gross < game_floor {
        return Err(RegError::GrossBelowFloor);
    }
    if inp.duration < MIN_DURATION || inp.duration > MAX_DURATION {
        return Err(RegError::DurationOutOfRange);
    }
    // deadline >= now + duration + voting_period + DEADLINE_MARGIN.
    let min_deadline = inp
        .now
        .checked_add(inp.duration)
        .and_then(|t| t.checked_add(inp.voting_period))
        .and_then(|t| t.checked_add(DEADLINE_MARGIN))
        .ok_or(RegError::TimeOverflow)?;
    if inp.deadline < min_deadline {
        return Err(RegError::DeadlineTooTight);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: u64 = 1_860_000;
    const VP: i64 = 120;

    fn inputs(gross: u64, duration: i64, deadline: i64) -> RegInputs {
        RegInputs {
            gross,
            duration,
            deadline,
            voting_period: VP,
            now: 1_000,
        }
    }

    /// A deadline exactly at the minimum for the given duration.
    fn tight_deadline(now: i64, duration: i64) -> i64 {
        now + duration + VP + DEADLINE_MARGIN
    }

    #[test]
    fn a_valid_registration_passes() {
        let inp = inputs(FLOOR, 600, tight_deadline(1_000, 600));
        assert_eq!(validate_registration(FLOOR, &inp), Ok(()));
    }

    #[test]
    fn refusals_are_checked_in_order() {
        // The floor beats every later check.
        let bad = inputs(0, 0, 0); // also bad duration, tight deadline
        assert_eq!(
            validate_registration(FLOOR, &bad),
            Err(RegError::GrossBelowFloor)
        );
        // Exactly one unit under the floor still fails.
        let inp = inputs(FLOOR - 1, 600, tight_deadline(1_000, 600));
        assert_eq!(
            validate_registration(FLOOR, &inp),
            Err(RegError::GrossBelowFloor)
        );
        // At the floor, the timeline is what decides.
        let inp = inputs(FLOOR, 0, tight_deadline(1_000, 600));
        assert_eq!(
            validate_registration(FLOOR, &inp),
            Err(RegError::DurationOutOfRange)
        );
    }

    #[test]
    fn duration_bounds_are_inclusive() {
        for (d, ok) in [
            (MIN_DURATION - 1, false),
            (MIN_DURATION, true),
            (MAX_DURATION, true),
            (MAX_DURATION + 1, false),
        ] {
            let inp = inputs(FLOOR, d, tight_deadline(1_000, d));
            let got = validate_registration(FLOOR, &inp);
            if ok {
                assert_eq!(got, Ok(()), "duration {d} should pass");
            } else {
                assert_eq!(got, Err(RegError::DurationOutOfRange), "duration {d}");
            }
        }
    }

    #[test]
    fn deadline_boundary_is_exact() {
        let now = 1_000;
        let duration = 600;
        let min = tight_deadline(now, duration);
        // Exactly the minimum passes.
        let ok = RegInputs {
            deadline: min,
            ..inputs(FLOOR, duration, min)
        };
        assert_eq!(validate_registration(FLOOR, &ok), Ok(()));
        // One second under fails.
        let tight = RegInputs {
            deadline: min - 1,
            ..inputs(FLOOR, duration, min)
        };
        assert_eq!(
            validate_registration(FLOOR, &tight),
            Err(RegError::DeadlineTooTight)
        );
    }

    #[test]
    fn deadline_time_overflow_is_reported() {
        let inp = RegInputs {
            now: i64::MAX,
            duration: MIN_DURATION,
            deadline: i64::MAX,
            voting_period: VP,
            gross: FLOOR,
        };
        assert_eq!(
            validate_registration(FLOOR, &inp),
            Err(RegError::TimeOverflow)
        );
    }
}
