//! Registration validation at materialization (funding spec §Тайминги,
//! §Константы). Unlike tasks there is no recipient profile and no reputation
//! gate — a collection's contributions are free-floating. Checked, in order: the
//! contribution clears the game floor, the funding `duration` is in range, and
//! the first contribution's escrow `deadline` leaves room for the whole lifecycle
//! (`created_at + duration + voting_period + DEADLINE_MARGIN`). Pure, ordered,
//! `checked` arithmetic — an unrepresentable instant is `TimeOverflow`, not a panic.

use conditional_funding_logic::{MAX_DURATION, MIN_DURATION};

/// Donor-UI safety margin (funding spec §Тайминги: 72h). Kept out of `logic/`
/// (harness: it is a registration gate, not a state-machine input) — the
/// on-chain `refund()` is the real safety net; this only spares a donor a
/// premature refund racing a settle.
pub const DEADLINE_MARGIN_SECS: u64 = 72 * 60 * 60;

/// Inputs gating materialization of a collection from its first contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegInputs {
    /// The first contribution's `gross`, pinned by the birth proof at the derived
    /// escrow address (so it is a fact, not a claim).
    pub gross: u64,
    /// Funding-window length (seconds), signed by the recipient in `create`.
    pub duration: u64,
    /// Voting-window length (seconds), from config, baked into `collection_id`.
    pub voting_period: u64,
    /// Birth time of the first funded contribution (slot→unix seconds); the
    /// collection's `created_at`.
    pub created_at: u64,
    /// The first contribution's escrow `deadline` (unix seconds).
    pub deadline: i64,
}

/// Registration refusals, in the exact order they are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegError {
    GrossBelowFloor,
    DurationOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
}

/// Validate a materialization: the floor, then duration in range, then the
/// deadline margin.
///
/// The floor is first because it is the cheapest check and the one that bounds
/// cost: one signature is shared by the collection's `N` contributions, but `N`
/// may be 1, and then nothing amortizes it (`cost.md §5,§6`).
pub fn validate_registration(inp: &RegInputs, min_gross: u64) -> Result<(), RegError> {
    if inp.gross < min_gross {
        return Err(RegError::GrossBelowFloor);
    }
    if inp.duration < MIN_DURATION || inp.duration > MAX_DURATION {
        return Err(RegError::DurationOutOfRange);
    }
    // deadline >= created_at + duration + voting_period + DEADLINE_MARGIN.
    let min_deadline = inp
        .created_at
        .checked_add(inp.duration)
        .and_then(|t| t.checked_add(inp.voting_period))
        .and_then(|t| t.checked_add(DEADLINE_MARGIN_SECS))
        .ok_or(RegError::TimeOverflow)?;
    let min_deadline = i64::try_from(min_deadline).map_err(|_| RegError::TimeOverflow)?;
    if inp.deadline < min_deadline {
        return Err(RegError::DeadlineTooTight);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VP: u64 = 120;
    const CREATED: u64 = 1_000_000;
    const FLOOR: u64 = 410_000;

    fn tight_deadline(created: u64, duration: u64) -> i64 {
        (created + duration + VP + DEADLINE_MARGIN_SECS) as i64
    }

    fn inputs(duration: u64, deadline: i64) -> RegInputs {
        RegInputs {
            gross: FLOOR,
            duration,
            voting_period: VP,
            created_at: CREATED,
            deadline,
        }
    }

    #[test]
    fn a_valid_registration_passes() {
        let inp = inputs(600, tight_deadline(CREATED, 600));
        assert_eq!(validate_registration(&inp, FLOOR), Ok(()));
    }

    #[test]
    fn the_floor_is_checked_first_and_its_boundary_is_inclusive() {
        let ok = inputs(600, tight_deadline(CREATED, 600));
        // At the floor → passes; one unit below → refused.
        assert_eq!(validate_registration(&ok, FLOOR), Ok(()));
        let mut dust = ok;
        dust.gross = FLOOR - 1;
        assert_eq!(
            validate_registration(&dust, FLOOR),
            Err(RegError::GrossBelowFloor)
        );
        // Below the floor *and* otherwise invalid → the floor is what is reported:
        // the cheapest refusal comes first, so a doomed dust call does no more work.
        let mut both = dust;
        both.duration = MAX_DURATION + 1;
        assert_eq!(
            validate_registration(&both, FLOOR),
            Err(RegError::GrossBelowFloor)
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
            let inp = inputs(d, tight_deadline(CREATED, d));
            let got = validate_registration(&inp, FLOOR);
            if ok {
                assert_eq!(got, Ok(()), "duration {d} should pass");
            } else {
                assert_eq!(got, Err(RegError::DurationOutOfRange), "duration {d}");
            }
        }
    }

    #[test]
    fn deadline_boundary_is_exact() {
        let duration = 600;
        let min = tight_deadline(CREATED, duration);
        assert_eq!(validate_registration(&inputs(duration, min), FLOOR), Ok(()));
        assert_eq!(
            validate_registration(&inputs(duration, min - 1), FLOOR),
            Err(RegError::DeadlineTooTight)
        );
    }

    #[test]
    fn deadline_time_overflow_is_reported() {
        let inp = RegInputs {
            gross: FLOOR,
            duration: MIN_DURATION,
            voting_period: VP,
            created_at: u64::MAX,
            deadline: i64::MAX,
        };
        assert_eq!(
            validate_registration(&inp, FLOOR),
            Err(RegError::TimeOverflow)
        );
    }
}
