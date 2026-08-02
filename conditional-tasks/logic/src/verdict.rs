//! Verdict rule (tasks spec §Правило вердикта).

use crate::machine::{Outcome, Vote};

/// `Cancel` ⇔ `Σweight(not_done)` **strictly** greater than `Σweight(done)`;
/// else `Settle` — including a tie and an empty vote. Silence pays the
/// recipient: stopping the money takes an actual `not_done` majority, not the
/// absence of voters. No quorum; the tally is total (a task always finalizes in
/// `Decided`).
///
/// A `checked_add` overflow is the one exception and still `Cancel`: it is a
/// failure of the tally, not a verdict of the voters, and settling on it would
/// let crafted weights force a payout.
pub fn verdict(votes: &[Vote]) -> Outcome {
    let mut done: u128 = 0;
    let mut not_done: u128 = 0;
    for v in votes {
        let bucket = if v.done { &mut done } else { &mut not_done };
        match bucket.checked_add(v.weight) {
            Some(sum) => *bucket = sum,
            None => return Outcome::Cancel, // overflow → not a verdict, refuse to pay
        }
    }
    if not_done > done {
        Outcome::Cancel
    } else {
        Outcome::Settle
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        assert_eq!(verdict(&[]), Outcome::Settle);
    }

    #[test]
    fn tie_settles() {
        let votes = [vote(500, true), vote(500, false)];
        assert_eq!(verdict(&votes), Outcome::Settle);
    }

    #[test]
    fn a_strict_not_done_majority_cancels() {
        assert_eq!(
            verdict(&[vote(500, true), vote(501, false)]),
            Outcome::Cancel
        );
        // One unit less (a tie) does not — it settles.
        assert_eq!(
            verdict(&[vote(500, true), vote(500, false)]),
            Outcome::Settle
        );
    }

    #[test]
    fn only_not_done_is_cancel() {
        assert_eq!(verdict(&[vote(1_000, false)]), Outcome::Cancel);
    }

    #[test]
    fn only_done_settles() {
        assert_eq!(verdict(&[vote(1_000, true)]), Outcome::Settle);
    }

    #[test]
    fn overflow_of_the_done_sum_is_cancel() {
        let votes = [vote(u128::MAX, true), vote(1, true)];
        assert_eq!(verdict(&votes), Outcome::Cancel);
    }

    #[test]
    fn overflow_of_the_not_done_sum_is_cancel() {
        let votes = [vote(u128::MAX, false), vote(1, false)];
        assert_eq!(verdict(&votes), Outcome::Cancel);
    }

    proptest! {
        /// With bounded weights (no overflow), `Cancel` iff the not-done sum
        /// strictly exceeds the done sum; everything else settles.
        #[test]
        fn cancel_iff_not_done_strictly_greater(
            done_weights in prop::collection::vec(1u128..1_000_000, 0..40),
            not_done_weights in prop::collection::vec(1u128..1_000_000, 0..40),
        ) {
            let mut votes = Vec::new();
            for w in &done_weights { votes.push(vote(*w, true)); }
            for w in &not_done_weights { votes.push(vote(*w, false)); }
            let done: u128 = done_weights.iter().sum();
            let not_done: u128 = not_done_weights.iter().sum();
            let expected = if not_done > done { Outcome::Cancel } else { Outcome::Settle };
            prop_assert_eq!(verdict(&votes), expected);
        }
    }
}
