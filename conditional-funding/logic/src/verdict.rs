//! Verdict with quorum (funding spec §Правило вердикта).

use crate::machine::{Outcome, Vote};
use crate::APPROVAL_THRESHOLD_SCALE;

/// `refund` ⇔ turnout `>= quorum_weight` **and** `yes·10000 < approval_threshold
/// ·turnout` (strict). Everything else settles: a tie, an undershoot of quorum,
/// an empty vote (a collection always finalizes). Silence pays the recipient —
/// refusing the payout takes a quorate vote that actually comes out against it.
///
/// The quorum therefore no longer guards the donor; it only gates whether the
/// approval share is consulted at all. It stays an absolute weight over **both**
/// sides (`yes+no`), not a fraction of the funded total — the canister is blind
/// to how much was raised.
///
/// A counting overflow is the one exception and still `refund`: it is a failure
/// of the tally, not a verdict of the voters, and settling on it would let
/// crafted weights force a payout.
pub fn verdict(votes: &[Vote], quorum_weight: u128, approval_threshold: u16) -> Outcome {
    let mut yes: u128 = 0;
    let mut no: u128 = 0;
    for v in votes {
        let bucket = if v.done { &mut yes } else { &mut no };
        match bucket.checked_add(v.weight) {
            Some(sum) => *bucket = sum,
            None => return Outcome::Refund,
        }
    }
    let turnout = match yes.checked_add(no) {
        Some(t) => t,
        None => return Outcome::Refund,
    };
    if turnout < quorum_weight {
        return Outcome::Settle;
    }
    // Non-strict: settle unless yes·10000 falls short of approval_threshold·turnout.
    let share = match yes.checked_mul(u128::from(APPROVAL_THRESHOLD_SCALE)) {
        Some(s) => s,
        None => return Outcome::Refund,
    };
    let bar = match u128::from(approval_threshold).checked_mul(turnout) {
        Some(b) => b,
        None => return Outcome::Refund,
    };
    if share >= bar {
        Outcome::Settle
    } else {
        Outcome::Refund
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic, not the hot path
mod tests {
    use super::*;
    use proptest::prelude::*;

    const Q: u128 = 150_000; // quorum
    const T: u16 = 5_000; // half — a tie clears it

    fn vote(weight: u128, done: bool) -> Vote {
        Vote {
            voter: [0; 32],
            weight,
            done,
        }
    }

    #[test]
    fn empty_settles() {
        // No voters at all → the recipient is paid; silence is not a veto.
        assert_eq!(verdict(&[], Q, T), Outcome::Settle);
    }

    #[test]
    fn undershooting_quorum_settles() {
        // A landslide yes below quorum → settle.
        assert_eq!(verdict(&[vote(Q - 1, true)], Q, T), Outcome::Settle);
        // And so does an all-no vote below quorum: an inquorate "no" cannot stop
        // the payout — this is the branch that used to protect the donor.
        assert_eq!(verdict(&[vote(Q - 1, false)], Q, T), Outcome::Settle);
        // One unit of weight more and the same all-no vote is quorate → refund.
        assert_eq!(verdict(&[vote(Q, false)], Q, T), Outcome::Refund);
    }

    #[test]
    fn tie_settles_and_a_quorate_no_majority_refunds() {
        // 50/50 at quorum → tie → settle (non-strict ≥).
        assert_eq!(
            verdict(&[vote(Q, true), vote(Q, false)], Q, T),
            Outcome::Settle
        );
        // One unit over half on the "no" side → refund.
        assert_eq!(
            verdict(&[vote(Q, true), vote(Q + 1, false)], Q, T),
            Outcome::Refund
        );
    }

    #[test]
    fn a_higher_threshold_needs_more() {
        // 60% yes with a 70% threshold (7000) at quorum → refund.
        let votes = [vote(600_000, true), vote(400_000, false)];
        assert_eq!(verdict(&votes, Q, 7_000), Outcome::Refund);
        // Same votes at a 50% threshold → settle.
        assert_eq!(verdict(&votes, Q, 5_000), Outcome::Settle);
    }

    #[test]
    fn overflow_of_a_sum_is_refund() {
        assert_eq!(
            verdict(&[vote(u128::MAX, true), vote(1, true)], Q, T),
            Outcome::Refund
        );
    }

    #[test]
    fn every_counting_overflow_refunds() {
        // The existing test covers the yes-bucket add; here the remaining three
        // `checked_*` refund branches (a collection always finalizes, never panics).
        // no-bucket add overflow.
        assert_eq!(
            verdict(&[vote(u128::MAX, false), vote(1, false)], Q, T),
            Outcome::Refund
        );
        // turnout = yes + no overflow: each bucket is fine, their sum is not.
        assert_eq!(
            verdict(&[vote(u128::MAX, true), vote(1, false)], Q, T),
            Outcome::Refund
        );
        // share = yes·10000 overflow (quorum 0 → nothing is below it, so we pass the
        // turnout gate and reach the multiply).
        assert_eq!(verdict(&[vote(u128::MAX, true)], 0, T), Outcome::Refund);
        // bar = approval_threshold·turnout overflow (all-no → share = 0 is fine, so
        // the refund comes from the bar multiply, not an earlier branch).
        assert_eq!(verdict(&[vote(u128::MAX, false)], 0, T), Outcome::Refund);
    }

    proptest! {
        /// With bounded weights (no overflow), refund iff turnout ≥ quorum and
        /// `yes·10000 < threshold·turnout`; everything else settles.
        #[test]
        fn matches_the_rule(
            yes_w in prop::collection::vec(1u128..1_000_000, 0..30),
            no_w in prop::collection::vec(1u128..1_000_000, 0..30),
            quorum in 0u128..2_000_000,
            threshold in 5_000u16..10_000,
        ) {
            let mut votes = Vec::new();
            for w in &yes_w { votes.push(vote(*w, true)); }
            for w in &no_w { votes.push(vote(*w, false)); }
            let yes: u128 = yes_w.iter().sum();
            let no: u128 = no_w.iter().sum();
            let turnout = yes + no;
            let expected = if turnout >= quorum
                && yes * 10_000 < u128::from(threshold) * turnout
            {
                Outcome::Refund
            } else {
                Outcome::Settle
            };
            prop_assert_eq!(verdict(&votes, quorum, threshold), expected);
        }
    }
}
