//! Verdict rule (tasks spec §Правило вердикта).

use crate::machine::{Outcome, Vote};

/// `Settle` ⇔ `Σweight(done)` **strictly** greater than `Σweight(not_done)`;
/// else `Cancel` — including a tie, an empty vote, or a `checked_add` overflow.
/// No quorum; the tally is total (a task always finalizes in `Decided`).
pub fn verdict(votes: &[Vote]) -> Outcome {
    let mut done: u128 = 0;
    let mut not_done: u128 = 0;
    for v in votes {
        let bucket = if v.done { &mut done } else { &mut not_done };
        match bucket.checked_add(v.weight) {
            Some(sum) => *bucket = sum,
            None => return Outcome::Cancel, // overflow → the safe side
        }
    }
    if done > not_done {
        Outcome::Settle
    } else {
        Outcome::Cancel
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
    fn empty_is_cancel() {
        assert_eq!(verdict(&[]), Outcome::Cancel);
    }

    #[test]
    fn tie_is_cancel() {
        let votes = [vote(500, true), vote(500, false)];
        assert_eq!(verdict(&votes), Outcome::Cancel);
    }

    #[test]
    fn strictly_greater_done_settles() {
        assert_eq!(
            verdict(&[vote(501, true), vote(500, false)]),
            Outcome::Settle
        );
        // One unit less (a tie) does not.
        assert_eq!(
            verdict(&[vote(500, true), vote(500, false)]),
            Outcome::Cancel
        );
    }

    #[test]
    fn only_not_done_is_cancel() {
        assert_eq!(verdict(&[vote(1_000, false)]), Outcome::Cancel);
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
        /// With bounded weights (no overflow), `Settle` iff done sum strictly
        /// exceeds the not-done sum.
        #[test]
        fn settle_iff_done_strictly_greater(
            done_weights in prop::collection::vec(1u128..1_000_000, 0..40),
            not_done_weights in prop::collection::vec(1u128..1_000_000, 0..40),
        ) {
            let mut votes = Vec::new();
            for w in &done_weights { votes.push(vote(*w, true)); }
            for w in &not_done_weights { votes.push(vote(*w, false)); }
            let done: u128 = done_weights.iter().sum();
            let not_done: u128 = not_done_weights.iter().sum();
            let expected = if done > not_done { Outcome::Settle } else { Outcome::Cancel };
            prop_assert_eq!(verdict(&votes), expected);
        }
    }
}
