//! Vote tally of the winning lot (auction spec — two-outcome form). Identical to
//! the tasks rule: `settle ⇔ Σweight(done) > Σweight(not_done)` (strict). A tie,
//! an empty tally, or any counting overflow → `cancel` (a lot always finalizes).

use crate::machine::{Outcome, Vote};

/// `settle` iff the done-weight strictly exceeds the not-done-weight.
pub fn verdict(votes: &[Vote]) -> Outcome {
    let mut done: u128 = 0;
    let mut not_done: u128 = 0;
    for v in votes {
        let bucket = if v.done { &mut done } else { &mut not_done };
        match bucket.checked_add(v.weight) {
            Some(sum) => *bucket = sum,
            None => return Outcome::Cancel,
        }
    }
    if done > not_done {
        Outcome::Settle
    } else {
        Outcome::Cancel
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic, not the hot path
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
    fn empty_and_tie_are_cancel_strict_majority_settles() {
        assert_eq!(verdict(&[]), Outcome::Cancel);
        assert_eq!(
            verdict(&[vote(100, true), vote(100, false)]),
            Outcome::Cancel
        ); // tie
        assert_eq!(
            verdict(&[vote(101, true), vote(100, false)]),
            Outcome::Settle
        ); // one over
    }

    #[test]
    fn overflow_is_cancel() {
        assert_eq!(
            verdict(&[vote(u128::MAX, true), vote(1, true)]),
            Outcome::Cancel
        );
    }

    proptest! {
        #[test]
        fn matches_the_rule(
            done_w in prop::collection::vec(1u128..1_000_000, 0..30),
            not_w in prop::collection::vec(1u128..1_000_000, 0..30),
        ) {
            let mut votes = Vec::new();
            for w in &done_w { votes.push(vote(*w, true)); }
            for w in &not_w { votes.push(vote(*w, false)); }
            let done: u128 = done_w.iter().sum();
            let not: u128 = not_w.iter().sum();
            let expected = if done > not { Outcome::Settle } else { Outcome::Cancel };
            prop_assert_eq!(verdict(&votes), expected);
        }
    }
}
