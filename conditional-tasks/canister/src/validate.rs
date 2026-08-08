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

/// The half of the registration policy that does **not** read the clock: the
/// game floor and the duration range, in the spec order (floor first — it is the
/// cheapest refusal, so a doomed dust call does no more work than it must).
///
/// Split out so the boundary can run it (harness §6). Both refusals are permanent
/// facts about an escrow that already exists on chain: `gross` and `duration` are
/// committed by `task_id`, the escrow is immutable, and no passage of time turns
/// either into an acceptance. Left to the update, one such registration was a
/// **flood template** — it never materializes, so `is_materialized` never starts
/// refusing it at the boundary, and the signed half of a request carries no nonce,
/// so a single doomed message is replayable forever and executed replicated every
/// time. `conditional-funding` already checked both at its boundary; the reference
/// game did not (`P8`).
///
/// The deadline check is the genuinely time-dependent one and stays in the update.
pub fn validate_time_free(game_floor: u64, gross: u64, duration: i64) -> Result<(), RegError> {
    if gross < game_floor {
        return Err(RegError::GrossBelowFloor);
    }
    if !(MIN_DURATION..=MAX_DURATION).contains(&duration) {
        return Err(RegError::DurationOutOfRange);
    }
    Ok(())
}

/// Validate a registration against the game floor and the timeline, in the spec
/// order: floor → duration → deadline. Authoritative; the boundary runs the
/// time-free prefix ([`validate_time_free`]) of exactly this, never a second copy
/// of it.
///
/// Every check here is a platform invariant, not a recipient preference. The
/// recipient's own terms (a minimum, a "not accepting", a reputation bar) are a
/// client-side filter and deliberately absent: this runs behind a birth proof,
/// so a refusal lands after the escrow is funded and paid for, where it costs
/// the donor and protects no one (`P7.14`; the remedy for an unwanted task is
/// `decline`, or the deadline's `refund()`).
pub fn validate_registration(game_floor: u64, inp: &RegInputs) -> Result<(), RegError> {
    validate_time_free(game_floor, inp.gross, inp.duration)?;
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

    /// The boundary runs `validate_time_free` and the update runs the whole
    /// thing, so the two must agree the way `State::admits` agrees with
    /// `apply_action`: every refusal the boundary makes is one the update makes
    /// too, and the boundary never refuses what the update would accept. Drift
    /// here is silent in both directions — a lost `false` is a flood template
    /// back, a spurious `false` is a valid registration dropped with no reason
    /// given to the client.
    #[test]
    fn the_time_free_prefix_agrees_with_the_full_check() {
        let now = 1_000;
        let cases = [
            (FLOOR, 600),                  // fine
            (FLOOR - 1, 600),              // below the floor
            (0, 600),                      // far below
            (FLOOR, MIN_DURATION - 1),     // duration too short
            (FLOOR, MAX_DURATION + 1),     // duration too long
            (FLOOR - 1, MAX_DURATION + 1), // both, floor reported first
            (FLOOR, MIN_DURATION),         // exact edges
            (FLOOR, MAX_DURATION),
        ];
        for (gross, duration) in cases {
            // A deadline generous enough that only the time-free half can fail.
            let inp = RegInputs {
                gross,
                duration,
                deadline: tight_deadline(now, duration.max(0)),
                voting_period: VP,
                now,
            };
            let prefix = validate_time_free(FLOOR, gross, duration);
            let full = validate_registration(FLOOR, &inp);
            match prefix {
                Err(e) => assert_eq!(
                    full,
                    Err(e),
                    "boundary refused ({gross}, {duration}) with {e:?}; the update must too"
                ),
                Ok(()) => assert_eq!(
                    full,
                    Ok(()),
                    "boundary admitted ({gross}, {duration}) the update then refused"
                ),
            }
        }
    }

    /// …and the one refusal the boundary is *not* allowed to make, because time
    /// can undo it: a deadline is tight relative to `now`, and `now` moves.
    #[test]
    fn the_time_free_prefix_says_nothing_about_the_deadline() {
        let now = 1_000;
        let duration = 600;
        let inp = RegInputs {
            gross: FLOOR,
            duration,
            deadline: tight_deadline(now, duration) - 1,
            voting_period: VP,
            now,
        };
        assert_eq!(
            validate_registration(FLOOR, &inp),
            Err(RegError::DeadlineTooTight)
        );
        assert_eq!(
            validate_time_free(FLOOR, inp.gross, inp.duration),
            Ok(()),
            "the boundary is clock-free and must not pre-judge the deadline"
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
