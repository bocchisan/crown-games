//! Registration validation (tasks spec §Валидация регистрации). A pure, ordered
//! sequence of refusals; the boundary is exact (the minimum passes, one second
//! under fails). Time arithmetic is `checked` — an unrepresentable instant is
//! `TimeOverflow`, not a panic.

use conditional_tasks_logic::{DEADLINE_MARGIN, MAX_DURATION, MIN_DURATION};

/// A recipient profile as it bears on registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub enabled: bool,
    pub min_gross: u64,
    pub min_reputation: u128,
}

/// The registration inputs that gate acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegInputs {
    pub gross: u64,
    pub duration: i64,
    pub deadline: i64,
    pub voting_period: i64,
    pub now: i64,
    /// Donor reputation from a local proof; consulted only when the profile
    /// requires it (`min_reputation > 0`).
    pub donor_reputation: Option<u128>,
}

/// Registration refusals, in the exact order they are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegError {
    ProfileDisabled,
    GrossBelowFloor,
    GrossBelowMinimum,
    ReputationBelowMinimum,
    DurationOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
}

/// Validate a registration against the recipient's profile and the game floor,
/// in the spec order: disabled → floor → profile-minimum → reputation →
/// duration → deadline. A missing reputation proof, when required, is treated as
/// below the minimum.
pub fn validate_registration(
    profile: &Profile,
    game_floor: u64,
    inp: &RegInputs,
) -> Result<(), RegError> {
    if !profile.enabled {
        return Err(RegError::ProfileDisabled);
    }
    if inp.gross < game_floor {
        return Err(RegError::GrossBelowFloor);
    }
    if inp.gross < profile.min_gross {
        return Err(RegError::GrossBelowMinimum);
    }
    if profile.min_reputation > 0 {
        match inp.donor_reputation {
            Some(rep) if rep >= profile.min_reputation => {}
            _ => return Err(RegError::ReputationBelowMinimum),
        }
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

    fn default_profile() -> Profile {
        // The lazy default: enabled, min_gross = floor, no reputation gate.
        Profile {
            enabled: true,
            min_gross: FLOOR,
            min_reputation: 0,
        }
    }

    fn inputs(gross: u64, duration: i64, deadline: i64) -> RegInputs {
        RegInputs {
            gross,
            duration,
            deadline,
            voting_period: VP,
            now: 1_000,
            donor_reputation: None,
        }
    }

    /// A deadline exactly at the minimum for the given duration.
    fn tight_deadline(now: i64, duration: i64) -> i64 {
        now + duration + VP + DEADLINE_MARGIN
    }

    #[test]
    fn a_valid_default_registration_passes() {
        let inp = inputs(FLOOR, 600, tight_deadline(1_000, 600));
        assert_eq!(
            validate_registration(&default_profile(), FLOOR, &inp),
            Ok(())
        );
    }

    #[test]
    fn refusals_are_checked_in_order() {
        // Disabled beats everything.
        let disabled = Profile {
            enabled: false,
            ..default_profile()
        };
        let bad = inputs(0, 0, 0); // also below floor, bad duration, tight deadline
        assert_eq!(
            validate_registration(&disabled, FLOOR, &bad),
            Err(RegError::ProfileDisabled)
        );

        // Below the game floor beats the profile minimum.
        let inp = inputs(FLOOR - 1, 600, tight_deadline(1_000, 600));
        assert_eq!(
            validate_registration(&default_profile(), FLOOR, &inp),
            Err(RegError::GrossBelowFloor)
        );

        // Above floor but below the profile minimum.
        let strict = Profile {
            min_gross: FLOOR + 100,
            ..default_profile()
        };
        let inp = inputs(FLOOR + 1, 600, tight_deadline(1_000, 600));
        assert_eq!(
            validate_registration(&strict, FLOOR, &inp),
            Err(RegError::GrossBelowMinimum)
        );
    }

    #[test]
    fn reputation_is_gated_only_when_required() {
        let rep_profile = Profile {
            min_reputation: 500_000,
            ..default_profile()
        };
        let base = inputs(FLOOR, 600, tight_deadline(1_000, 600));

        // No proof supplied, but reputation is required → below minimum.
        assert_eq!(
            validate_registration(&rep_profile, FLOOR, &base),
            Err(RegError::ReputationBelowMinimum)
        );
        // Proof below the bar → below minimum.
        let low = RegInputs {
            donor_reputation: Some(499_999),
            ..base
        };
        assert_eq!(
            validate_registration(&rep_profile, FLOOR, &low),
            Err(RegError::ReputationBelowMinimum)
        );
        // Proof exactly at the bar → passes.
        let ok = RegInputs {
            donor_reputation: Some(500_000),
            ..base
        };
        assert_eq!(validate_registration(&rep_profile, FLOOR, &ok), Ok(()));
        // When min_reputation == 0, no proof is needed (default profile above).
        assert_eq!(
            validate_registration(&default_profile(), FLOOR, &base),
            Ok(())
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
            let got = validate_registration(&default_profile(), FLOOR, &inp);
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
        assert_eq!(
            validate_registration(&default_profile(), FLOOR, &ok),
            Ok(())
        );
        // One second under fails.
        let tight = RegInputs {
            deadline: min - 1,
            ..inputs(FLOOR, duration, min)
        };
        assert_eq!(
            validate_registration(&default_profile(), FLOOR, &tight),
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
            donor_reputation: None,
            gross: FLOOR,
        };
        assert_eq!(
            validate_registration(&default_profile(), FLOOR, &inp),
            Err(RegError::TimeOverflow)
        );
    }
}
