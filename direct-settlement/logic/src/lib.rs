#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
//! direct-settlement logic — the split arithmetic and the two floors, zero-dep.
//!
//! The game has no canister and no program of its own (spec §Что это): a donation
//! is one Solana transaction carrying two instructions the client assembles — the
//! fee transfer and `splitter.donate(net)`. What *is* real code is the arithmetic
//! around it, and it has to be identical in two places that never talk to each
//! other:
//!
//! - the **client**, which computes `(fee, net)` before asking the donor to sign;
//! - the **submitter**, which looks at a finished transaction and decides whether
//!   to spend `INGEST_PRICE` folding it into the book ([`payable`]).
//!
//! Those two agreeing is the whole non-negativity argument of this game (spec
//! §Не-отрицательность): we pay to index only what already paid us, and the floor
//! is the number that makes "already paid us" exceed "what indexing costs". A
//! drift between the two readings would not fail a test — it would show up as a
//! cycle bill, which is why the arithmetic lives here once instead of twice.

/// Version of the rules. Bumped only by a deliberate change to the split or the
/// floors — there is no state machine here to version.
pub const LOGIC_VERSION: u32 = 1;

/// Platform fee, ten-thousandths. 2% — lower than the escrow games' 3% because
/// this settlement costs the platform one book write and nothing else: no
/// threshold signature, no birth, no escrow rent (spec §Экономика).
pub const FEE_BPS: u16 = 200;

/// Denominator and exclusive upper bound of a fee in ten-thousandths.
pub const FEE_SCALE: u32 = 10_000;

/// The index's dust floor (`crown-indexer` `config.min_gross`, $0.20 in USDC
/// minor units). A settlement whose `gross` — here the **net**, since that is
/// what the splitter moves and reports — falls below it is dropped as dust and
/// never becomes reputation. Copied rather than imported: the index is a separate
/// repo and this crate is zero-dep by contract. It is a *lower* bound we stay
/// above by a wide margin, so a copy going stale under us cannot silently start
/// admitting dust — it would have to be raised past `MIN_GROSS·(1 − fee)`, which
/// [`the_floor_clears_the_index_dust_floor`] pins.
pub const INDEX_MIN_GROSS: u64 = 200_000;

/// Cost of folding one direct settlement, in USDC minor units: one SOL RPC
/// `getTransaction` (`cost.md §1`, `g = 7_038_843_200` cycles at the protocol peg
/// `1e12 cycles = $1.36643`) ≈ $0.009618.
///
/// A direct settlement has no other cost term: no birth to write (nothing was
/// created), no verdict signature to buy (nothing here is a scope), no votes —
/// which is the whole reason this game's floor is a quarter of the escrow games'.
pub const SETTLEMENT_COST: u64 = 9_618;

/// Floor margin over the raw break-even, ten-thousandths (`cost.md §5`, frozen
/// policy `MARGIN = 20%`).
pub const MARGIN_BPS: u16 = 2_000;

/// Platform floor on a donation we will index, mainnet, USDC minor units.
///
/// Derived, not chosen: `break_even = SETTLEMENT_COST / (FEE_BPS/10000)` =
/// $0.4809, times `1 + MARGIN` = **$0.5771**, rounded up to the next legible
/// hundredth. [`the_floor_clears_break_even`] recomputes it, so a change to the
/// fee, the margin or the measured cost turns red here rather than in a cycle
/// bill six months later.
///
/// Devnet runs pass their own (`250_000`, spec §Константы) — every function here
/// takes the floor as an argument for exactly that reason.
pub const MIN_GROSS: u64 = 580_000;

/// What the donor's transaction moves, in USDC minor units. `fee + net == gross`
/// exactly — the split has no remainder by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Split {
    /// To the platform's fee wallet, by a plain transfer that bypasses the
    /// splitter: money through the splitter is a `Settled`, and a fee that
    /// emitted one would mint reputation for the fee wallet out of nothing.
    pub fee: u64,
    /// To the recipient, through the splitter. This is what the book records and
    /// what the donor's reputation is credited with — not `gross`.
    pub net: u64,
}

/// Why a donation is not one we will index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `fee_bps` outside `[0, FEE_SCALE)` — a fee of 100% or more is not a fee.
    BadFee,
    /// Below the platform floor: the fee would not cover what indexing costs.
    GrossBelowFloor,
    /// The net falls under the index's dust floor, so folding it would buy
    /// nothing — the index drops it either way.
    NetBelowIndexFloor,
    /// The fee actually transferred is short of the one this `gross` owes.
    FeeUnderpaid,
}

/// Split `gross` into `(fee, net)`. `None` only on a nonsensical `fee_bps`.
///
/// The fee **floors**, so the rounding remainder goes to the recipient rather
/// than to us: at these sizes it is at most one minor unit, and the direction is
/// the one nobody has to argue about.
pub fn split(gross: u64, fee_bps: u16) -> Option<Split> {
    if u32::from(fee_bps) >= FEE_SCALE {
        return None;
    }
    let fee = u128::from(gross)
        .checked_mul(u128::from(fee_bps))?
        .checked_div(u128::from(FEE_SCALE))?;
    let fee = u64::try_from(fee).ok()?;
    let net = gross.checked_sub(fee)?;
    Some(Split { fee, net })
}

/// The client's gate: what this `gross` splits into, or why it will not be
/// accepted. Checked in cost order — the fee shape, then the platform floor, then
/// the index's.
pub fn quote(gross: u64, fee_bps: u16, min_gross: u64) -> Result<Split, Refusal> {
    let s = split(gross, fee_bps).ok_or(Refusal::BadFee)?;
    if gross < min_gross {
        return Err(Refusal::GrossBelowFloor);
    }
    if s.net < INDEX_MIN_GROSS {
        return Err(Refusal::NetBelowIndexFloor);
    }
    Ok(s)
}

/// The submitter's gate, and the load-bearing one: **is this finished transaction
/// worth spending `INGEST_PRICE` on?**
///
/// Inputs are what the chain shows, not what anyone claims: `net` is the amount
/// the splitter moved (the `Settled` the index will read), `fee_paid` is the
/// USDC that actually landed on the fee wallet's token account under the same
/// donor authority. `gross` is reconstructed as their sum, and that
/// reconstruction is exact rather than approximate — [`split`] defines
/// `net = gross − floor(gross·bps/10000)`, so `net + fee` returns the original
/// `gross` with no rounding drift, which [`a_quoted_split_is_always_payable`]
/// pins over the whole range.
///
/// **This is the anti-flood mechanism of the game, and it is the only one it
/// needs.** There is nothing of ours a stranger can execute: no canister, no
/// ingress, no program. The single way to make this game cost us money is to get
/// us to buy an ingest — and we only buy one after this returns `Ok`, i.e. after
/// the sender has already paid us more than the ingest burns. Overpaying is
/// allowed; underpaying is not indexed, and the donation still stands on chain
/// (spec §Не-отрицательность).
pub fn payable(net: u64, fee_paid: u64, fee_bps: u16, min_gross: u64) -> Result<(), Refusal> {
    let Some(gross) = net.checked_add(fee_paid) else {
        return Err(Refusal::BadFee); // unreachable on real amounts; never a panic
    };
    let owed = split(gross, fee_bps).ok_or(Refusal::BadFee)?;
    if gross < min_gross {
        return Err(Refusal::GrossBelowFloor);
    }
    if net < INDEX_MIN_GROSS {
        return Err(Refusal::NetBelowIndexFloor);
    }
    if fee_paid < owed.fee {
        return Err(Refusal::FeeUnderpaid);
    }
    Ok(())
}

#[cfg(test)]
// Test arithmetic, not the hot path; and `expect` in a test **is** the assertion —
// the crate-level ban stays unconditional for everything that ships.
#[allow(clippy::arithmetic_side_effects, clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn the_split_is_exact_and_the_remainder_goes_to_the_recipient() {
        let s = split(1_000_000, FEE_BPS).expect("2% of $1");
        assert_eq!(s.fee, 20_000, "2% of 1.000000 USDC");
        assert_eq!(s.net, 980_000);
        assert_eq!(s.fee + s.net, 1_000_000, "no remainder");

        // 49 minor units at 2% is 0.98 of a unit — it floors to 0, and the whole
        // amount reaches the recipient. The direction is deliberate.
        let dust = split(49, FEE_BPS).expect("valid bps");
        assert_eq!((dust.fee, dust.net), (0, 49));

        assert_eq!(split(1, 10_000), None, "a fee of 100% is not a fee");
        assert_eq!(split(u64::MAX, FEE_BPS).map(|s| s.fee), Some(u64::MAX / 50));
    }

    /// The floor is a derivation, and this is the derivation. It goes red if the
    /// fee is cut, the margin is cut, or the measured cost of a book write rises
    /// — each of which silently turns every donation at the floor into a loss.
    #[test]
    fn the_floor_clears_break_even() {
        let earned = split(MIN_GROSS, FEE_BPS).expect("valid bps").fee;
        let required = u128::from(SETTLEMENT_COST) * u128::from(FEE_SCALE + u32::from(MARGIN_BPS));
        assert!(
            u128::from(earned) * u128::from(FEE_SCALE) >= required,
            "at the floor the fee is {earned}, which no longer covers \
             {SETTLEMENT_COST} + {MARGIN_BPS}bps of margin"
        );
        // …and it is not wastefully far above it either: one cent lower would
        // still clear, so the floor is the model's number and not a round guess.
        let lower = split(MIN_GROSS - 10_000, FEE_BPS).expect("valid bps").fee;
        assert!(
            u128::from(lower) * u128::from(FEE_SCALE) < required,
            "the floor has a cent of slack — recompute it rather than padding"
        );
    }

    /// A donation at the floor must still be *worth* indexing: the index drops a
    /// settlement below its own dust floor, so a floor that let the net fall under
    /// it would have us paying for writes the book refuses.
    #[test]
    fn the_floor_clears_the_index_dust_floor() {
        let s = split(MIN_GROSS, FEE_BPS).expect("valid bps");
        assert!(
            s.net >= INDEX_MIN_GROSS,
            "net {} at the floor is below the index dust floor {INDEX_MIN_GROSS}",
            s.net
        );
        // The devnet floor (spec §Константы) has to clear it too — live runs are
        // cheap on purpose, but a run that produces no reputation proves nothing.
        let dev = split(250_000, FEE_BPS).expect("valid bps");
        assert!(
            dev.net >= INDEX_MIN_GROSS,
            "devnet floor must still be foldable"
        );
    }

    /// How much a sender can shave off the fee and still be indexed — the actual
    /// security bound of `payable`, and it is not the naive one.
    ///
    /// `gross` is *reconstructed* from what moved, so shaving the fee also shrinks
    /// the `gross` it is measured against, and part of the shave forgives itself.
    /// It converges rather than unravels: paying `f` on a delivered `net` is
    /// accepted only while `f ≥ (net+f)·bps/10000`, whose fixed point is exactly
    /// the honest split — leaving one minor unit of floor rounding and nothing
    /// else. That unit is $0.000001, so the bound is stated here rather than
    /// engineered away.
    #[test]
    fn the_fee_can_be_shaved_by_one_rounding_unit_and_no_more() {
        let s = split(1_000_000, FEE_BPS).expect("valid bps");
        assert_eq!(payable(s.net, s.fee, FEE_BPS, MIN_GROSS), Ok(()));
        // Overpaying is fine — a gift, not an error.
        assert_eq!(payable(s.net, s.fee + 1, FEE_BPS, MIN_GROSS), Ok(()));
        // One unit under still passes: it is simply a donation of `gross − 1`,
        // correctly paid, not a discount on this one.
        assert_eq!(payable(s.net, s.fee - 1, FEE_BPS, MIN_GROSS), Ok(()));
        // Two units under does not, and that is where it stops.
        assert_eq!(
            payable(s.net, s.fee - 2, FEE_BPS, MIN_GROSS),
            Err(Refusal::FeeUnderpaid)
        );
        // Half the fee, or none of it, is nowhere near — an unpaid direct
        // donation works on chain and is simply not ours to index.
        assert_eq!(
            payable(s.net, s.fee / 2, FEE_BPS, MIN_GROSS),
            Err(Refusal::FeeUnderpaid)
        );
        assert_eq!(
            payable(1_000_000, 0, FEE_BPS, MIN_GROSS),
            Err(Refusal::FeeUnderpaid)
        );
    }

    #[test]
    fn both_floors_refuse_before_the_fee_check() {
        // Under the platform floor: the fee is correct, but it does not cover the
        // write, so the answer is the floor and not the fee.
        let small = split(MIN_GROSS - 1, FEE_BPS).expect("valid bps");
        assert_eq!(
            payable(small.net, small.fee, FEE_BPS, MIN_GROSS),
            Err(Refusal::GrossBelowFloor)
        );
        // Under the index's dust floor with the platform floor waived (a devnet
        // profile could sit here): folding it would buy a row the index discards.
        assert_eq!(
            payable(199_999, 10_000_000, FEE_BPS, 0),
            Err(Refusal::NetBelowIndexFloor)
        );
        assert_eq!(
            quote(MIN_GROSS - 1, FEE_BPS, MIN_GROSS),
            Err(Refusal::GrossBelowFloor)
        );
        assert_eq!(quote(1_000, 0, 0), Err(Refusal::NetBelowIndexFloor));
    }

    proptest! {
        /// The property the two readings rest on: whatever the client quoted, the
        /// submitter accepts. If these ever disagree the failure is silent — a
        /// donor pays the fee and the reputation never appears, or we index
        /// something that paid us nothing.
        #[test]
        fn a_quoted_split_is_always_payable(gross in 0u64..1_000_000_000_000, bps in 0u16..10_000) {
            let Ok(s) = quote(gross, bps, MIN_GROSS) else { return Ok(()); };
            prop_assert_eq!(s.fee + s.net, gross, "the split must be exact");
            prop_assert_eq!(payable(s.net, s.fee, bps, MIN_GROSS), Ok(()));
        }

        /// `net + fee` recovers `gross` exactly, so the submitter reconstructs
        /// what the client started from and no rounding drifts between them.
        #[test]
        fn the_reconstruction_is_exact(gross in 0u64..1_000_000_000_000) {
            let s = split(gross, FEE_BPS).expect("valid bps");
            prop_assert_eq!(s.net + s.fee, gross);
            prop_assert_eq!(split(s.net + s.fee, FEE_BPS), Some(s));
        }

        /// The shaving bound, over the range rather than at one point: to be
        /// indexed while delivering `net`, the fee paid can fall no more than a
        /// rounding unit below `net·bps/(10000−bps)` — the honest fee expressed
        /// from the recipient's side. This is what stops "pay us a token amount
        /// and get the book write anyway".
        #[test]
        fn shaving_below_the_honest_fee_is_never_indexed(
            net in 200_000u64..1_000_000_000,
            fee_paid in any::<u64>(),
        ) {
            let honest = net * u64::from(FEE_BPS) / (u64::from(FEE_SCALE) - u64::from(FEE_BPS));
            if payable(net, fee_paid, FEE_BPS, MIN_GROSS).is_ok() {
                prop_assert!(
                    fee_paid + 1 >= honest,
                    "indexed while paying {fee_paid} where {honest} was owed on a net of {net}"
                );
            }
        }

        /// Nothing here panics on any input — the submitter runs it over whatever
        /// the chain hands it.
        #[test]
        fn no_input_panics(a in any::<u64>(), b in any::<u64>(), bps in any::<u16>()) {
            let _ = split(a, bps);
            let _ = quote(a, bps, b);
            let _ = payable(a, b, bps, MIN_GROSS);
        }
    }
}
