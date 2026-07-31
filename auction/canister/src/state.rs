//! Canister state + orchestration (in-memory). A new version is a fresh canister
//! (harness §7 bars migration), so heap state is correct. Registryless at the
//! escrow level: an auction holds its lots, a lot holds its confirmed entries
//! (each escrow carries its own leaf scope `resolver = key([entry_id])`, so a
//! verdict names exactly one escrow — a lot is the contest group). The machine
//! (`auction-logic`) gates by auction state; the value/role gates live here —
//! `gross ≥ min_entry` (in `validate`), lot-not-returned, accept-not-already-
//! accepted, entry-not-returned. Host-testable pure operations under thin
//! `ic_cdk` wrappers.
//!
//! The winner is arithmetic, so unlike every other game here the canister is
//! **not** blind to amounts: a confirmed entry stores its `gross` and its lot
//! keeps the running `total`. Both are trustworthy without reading the chain —
//! `gross` is committed by the escrow's address salt and the index only emits a
//! birth for a `create_escrow` cross-checked against an executed transfer of
//! exactly that amount, so a lied-about `gross` derives an address no birth
//! lives at (`admit_register_entry`).

use auction_logic::{step, tick, Action, Auction, Known, State, StepError};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// A confirmed contribution to a lot. Only the fields the resolution and the
/// close read are kept: `returned` (liveness), `escrow` (identity/dedup),
/// `entry_id` — the entry's leaf scope, under which its verdict is signed
/// (`resolver = key([entry_id])`) — and `gross`, which is what it weighs at the
/// close.
#[derive(Clone)]
struct StoredEntry {
    returned: Option<u64>,
    escrow: [u8; 32],
    entry_id: [u8; 32],
    gross: u64,
}

/// A lot: its contest key (`lot_id`), its `text_hash`, the confirmed entries, and
/// `total` — the sum of the live ones, which is what the close compares. A lot
/// holds no resolver: the resolver lives at the entry (its settlement leaf).
///
/// `total` is maintained incrementally (add on a confirmed entry, subtract on a
/// `return_entry`) rather than summed on demand, so the standing costs nothing to
/// read and the close is one pass over lots instead of over every contribution.
#[derive(Clone)]
struct StoredLot {
    lot_id: [u8; 32],
    text_hash: [u8; 32],
    accepted_at: Option<u64>,
    returned: Option<u64>,
    total: u128,
    entries: Vec<StoredEntry>,
}

/// A materialized auction: the logic machine, the recipient (authorizes
/// accept/return/cancel), the `min_entry` snapshot, and the lots.
#[derive(Clone)]
struct StoredAuction {
    auction: Auction,
    recipient: [u8; 32],
    min_entry: u64,
    lots: Vec<StoredLot>,
}

// The verdict signature store and its claim-before-await discipline live in
// `crown_games_common::signing` — non-negativity invariant #5, one mechanism
// for every game rather than three byte-identical copies (`P7.6`).
pub use crown_games_common::signing::SignedVerdict;

thread_local! {
    static AUCTIONS: RefCell<BTreeMap<[u8; 32], StoredAuction>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// An auction as a caller sees it: the state with the accrued close applied, plus
/// `closes_at` — the instant the window shuts and the heaviest lot wins.
///
/// `closes_at` is on every reply and not just the query because it is the one
/// number the whole game turns on and nothing else exposes it: `created_at` is
/// fixed by the birth slot of whoever registered first, so the recipient's
/// published `duration` does **not** tell a bidder how long is left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub state: State,
    pub closes_at: u64,
}

/// State-level errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    AlreadyExists,
    NotFound,
    NotRecipient,
    LotNotFound,
    LotReturned,
    LotAlreadyAccepted,
    EntryNotFound,
    EntryReturned,
    DuplicateEscrow,
    TotalOverflow,
    Step(StepError),
}

// ---- helpers over the store ----

fn with_auction<R>(
    id: &[u8; 32],
    f: impl FnOnce(&mut StoredAuction) -> Result<R, StateError>,
) -> Result<R, StateError> {
    AUCTIONS.with_borrow_mut(|a| {
        let s = a.get_mut(id).ok_or(StateError::NotFound)?;
        f(s)
    })
}

fn find_lot<'a>(s: &'a mut StoredAuction, lot_id: &[u8; 32]) -> Option<&'a mut StoredLot> {
    s.lots.iter_mut().find(|l| l.lot_id == *lot_id)
}

/// The winning lot: the eligible lot with the greatest live total. Eligible =
/// accepted by the recipient, not returned, and still holding money (an accepted
/// lot whose every entry was returned weighs nothing and cannot win a settle over
/// an empty set of escrows).
///
/// One pass, and only ever at the close — the machine consults it lazily, and
/// `Done` is absorbing, so it runs at most once per auction. The set it reads is
/// frozen by then: every action that could move a total needs `Bidding`, which
/// `now ≥ T` has already left. So the winner does not depend on which call
/// happens to be the first one after `T`.
///
/// **Ties go to the lot that opened first** — the comparison is strict (`>`) over
/// insertion order, i.e. the order of each lot's first confirmed entry. A later
/// bid has to actually outbid, not merely match.
fn top_lot(lots: &[StoredLot]) -> Option<[u8; 32]> {
    let mut best: Option<&StoredLot> = None;
    for l in lots {
        if l.returned.is_some() || l.accepted_at.is_none() || l.total == 0 {
            continue;
        }
        let better = match best {
            None => true,
            Some(b) => l.total > b.total,
        };
        if better {
            best = Some(l);
        }
    }
    best.map(|l| l.lot_id)
}

/// Advance the clock, then apply `action`. The two field borrows are disjoint, so
/// the machine can mutate the auction while the close scan reads the lots.
/// The caller-visible view of an auction. `closes_at` saturates rather than
/// checking: it is a display value, and the authoritative arithmetic is the
/// machine's, which reports `Overflow` and refuses to move.
fn view(s: &StoredAuction) -> View {
    View {
        state: s.auction.state.clone(),
        closes_at: s.auction.created_at.saturating_add(s.auction.duration),
    }
}

fn step_now(s: &mut StoredAuction, action: Action, now: u64) -> Result<(), StateError> {
    let (auction, lots) = (&mut s.auction, &s.lots);
    step(auction, action, now, || top_lot(lots)).map_err(StateError::Step)
}

// ---- materialization + entries ----

pub fn is_materialized(auction_id: &[u8; 32]) -> bool {
    AUCTIONS.with_borrow(|a| a.contains_key(auction_id))
}

/// Materialize an auction from its first confirmed entry (state `Bidding`,
/// `created_at` fixed). Idempotent by `auction_id`.
pub fn materialize(
    auction_id: [u8; 32],
    auction: Auction,
    recipient: [u8; 32],
    min_entry: u64,
) -> Result<(), StateError> {
    AUCTIONS.with_borrow_mut(|a| {
        if a.contains_key(&auction_id) {
            return Err(StateError::AlreadyExists);
        }
        a.insert(
            auction_id,
            StoredAuction {
                auction,
                recipient,
                min_entry,
                lots: Vec::new(),
            },
        );
        Ok(())
    })
}

/// The auction's fixed `created_at` + rule snapshot (for the per-entry deadline
/// check on a top-up), or `None` if unknown.
pub fn timing(auction_id: &[u8; 32]) -> Option<(u64, u64, u64)> {
    AUCTIONS.with_borrow(|a| {
        a.get(auction_id)
            .map(|s| (s.auction.created_at, s.auction.duration, s.min_entry))
    })
}

/// Add a confirmed entry to its lot (creating the lot on first sight) and carry
/// its `gross` into the lot's running total. Gates: auction still `Bidding` (the
/// machine `RegisterEntry` step, which first applies the close), lot not returned,
/// escrow not already present.
pub fn add_entry(
    auction_id: &[u8; 32],
    text_hash: [u8; 32],
    lot_id: [u8; 32],
    entry_id: [u8; 32],
    escrow: [u8; 32],
    gross: u64,
    now: u64,
) -> Result<(), StateError> {
    with_auction(auction_id, |s| {
        // Machine gate: register only while the window is open (`now < T`).
        step_now(s, Action::RegisterEntry, now)?;
        // Escrow uniqueness across the auction (a duplicate birth proof is a
        // no-op — and would otherwise count one deposit toward the total twice).
        if s.lots
            .iter()
            .any(|l| l.entries.iter().any(|e| e.escrow == escrow))
        {
            return Err(StateError::DuplicateEscrow);
        }
        let entry = StoredEntry {
            returned: None,
            escrow,
            entry_id,
            gross,
        };
        match find_lot(s, &lot_id) {
            Some(lot) => {
                if lot.returned.is_some() {
                    return Err(StateError::LotReturned); // no top-up into a returned lot
                }
                // Checked, and refused rather than clamped: a saturating total
                // would silently tie at the ceiling and hand the close to the
                // insertion-order tiebreak instead of to the larger bid.
                lot.total = lot
                    .total
                    .checked_add(u128::from(gross))
                    .ok_or(StateError::TotalOverflow)?;
                lot.entries.push(entry);
            }
            None => s.lots.push(StoredLot {
                lot_id,
                text_hash,
                accepted_at: None,
                returned: None,
                total: u128::from(gross),
                entries: vec![entry],
            }),
        }
        Ok(())
    })
}

// ---- recipient actions ----

fn require_recipient(s: &StoredAuction, signer: &[u8; 32]) -> Result<(), StateError> {
    if s.recipient == *signer {
        Ok(())
    } else {
        Err(StateError::NotRecipient)
    }
}

/// `accept_lot` (recipient): the lot must exist, be unaccepted and unreturned;
/// gated `Bidding` by the machine. Sets `accepted_at = now`, which is what makes
/// the lot eligible to win the close.
pub fn accept_lot(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    lot_id: &[u8; 32],
    now: u64,
) -> Result<View, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        step_now(s, Action::AcceptLot, now)?;
        let lot = find_lot(s, lot_id).ok_or(StateError::LotNotFound)?;
        if lot.returned.is_some() {
            return Err(StateError::LotReturned);
        }
        if lot.accepted_at.is_some() {
            return Err(StateError::LotAlreadyAccepted);
        }
        lot.accepted_at = Some(now);
        Ok(view(s))
    })
}

/// `return_lot` (recipient): drop a lot out of the contest, only while `Bidding`.
/// The lot stops being eligible to win and every one of its entries resolves
/// `Cancel` (stage 2).
pub fn return_lot(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    lot_id: &[u8; 32],
    now: u64,
) -> Result<View, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        step_now(s, Action::ReturnLot, now)?;
        let lot = find_lot(s, lot_id).ok_or(StateError::LotNotFound)?;
        if lot.returned.is_some() {
            return Err(StateError::LotReturned);
        }
        lot.returned = Some(now);
        Ok(view(s))
    })
}

/// `return_entry` (recipient): return one specific entry's escrow, only while
/// `Bidding`. Its `gross` leaves the lot's total, so a returned contribution
/// stops counting toward the close.
pub fn return_entry(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    lot_id: &[u8; 32],
    escrow: &[u8; 32],
    now: u64,
) -> Result<View, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        step_now(s, Action::ReturnEntry, now)?;
        let lot = find_lot(s, lot_id).ok_or(StateError::LotNotFound)?;
        let entry = lot
            .entries
            .iter_mut()
            .find(|e| e.escrow == *escrow)
            .ok_or(StateError::EntryNotFound)?;
        if entry.returned.is_some() {
            return Err(StateError::EntryReturned);
        }
        entry.returned = Some(now);
        let gross = u128::from(entry.gross);
        // Cannot underflow — every live entry's `gross` was added to `total` and
        // is subtracted at most once (`EntryReturned` above) — but the money
        // arithmetic stays checked rather than resting on that argument.
        lot.total = lot
            .total
            .checked_sub(gross)
            .ok_or(StateError::TotalOverflow)?;
        Ok(view(s))
    })
}

/// `cancel_auction` (recipient): `Bidding → Done{winner_lot: None}`. Only before
/// the close — once the window shuts the winner is fixed and `Done` is absorbing.
pub fn cancel_auction(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    now: u64,
) -> Result<View, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        step_now(s, Action::CancelAuction, now)?;
        Ok(view(s))
    })
}

/// The stage-1 input: is `escrow` unknown to the auction, live, or returned.
pub fn entry_status(auction_id: &[u8; 32], lot_id: &[u8; 32], escrow: &[u8; 32]) -> Known {
    AUCTIONS.with_borrow(|a| {
        let Some(s) = a.get(auction_id) else {
            return Known::Unknown;
        };
        let Some(lot) = s.lots.iter().find(|l| l.lot_id == *lot_id) else {
            return Known::Unknown;
        };
        match lot.entries.iter().find(|e| e.escrow == *escrow) {
            Some(e) if e.returned.is_some() => Known::Returned,
            Some(_) => Known::Live,
            None => Known::Unknown,
        }
    })
}

/// The stage-2 input: is the lot unknown, live, or returned.
pub fn lot_status(auction_id: &[u8; 32], lot_id: &[u8; 32]) -> Known {
    AUCTIONS.with_borrow(|a| {
        let Some(s) = a.get(auction_id) else {
            return Known::Unknown;
        };
        match s.lots.iter().find(|l| l.lot_id == *lot_id) {
            Some(l) if l.returned.is_some() => Known::Returned,
            Some(_) => Known::Live,
            None => Known::Unknown,
        }
    })
}

// ---- reads ----

/// The already-committed fact about an action's *target* that the boundary adds
/// to the auction state (harness §6).
///
/// **Monotone is the entire requirement.** `accepted_at` and `returned` only ever
/// go `None → Some`, so a refusal here is one the update will still make when it
/// runs a round later. Facts that can *appear* between the boundary and execution
/// — an unknown lot, an unknown entry — are deliberately absent: refusing on them
/// would drop a call that a registration landing in the same round makes valid,
/// and a legitimate call dropped for free reads as a refusal without cause.
///
/// Without this the boundary admitted every action from the right signer, and the
/// doomed ones ran replicated at the canister's expense. That is not a one-off
/// cost: the signed half of a request carries **no nonce and no expiry**, so one
/// observed `accept_lot` is a template anyone can resubmit forever, each replay
/// buying a full Ed25519 verification plus a replicated round.
#[derive(Clone, Copy)]
pub enum Target {
    /// `accept_lot`: a lot already accepted, or already returned, is doomed.
    LotToAccept([u8; 32]),
    /// `return_lot`: a lot already returned is doomed.
    LotToReturn([u8; 32]),
    /// `return_entry`: an entry already returned is doomed. A *returned lot* is
    /// not — `return_entry` does not check it, and the boundary must stay a
    /// strict subset of the update.
    EntryToReturn([u8; 32], [u8; 32]),
    /// `cancel_auction`: it names no target, so the auction state is the whole
    /// check.
    Auction,
}

fn target_admits(s: &StoredAuction, target: Target) -> Result<(), StateError> {
    let lot = |id: &[u8; 32]| s.lots.iter().find(|l| l.lot_id == *id);
    match target {
        Target::Auction => Ok(()),
        Target::LotToAccept(lot_id) => match lot(&lot_id) {
            Some(l) if l.returned.is_some() => Err(StateError::LotReturned),
            Some(l) if l.accepted_at.is_some() => Err(StateError::LotAlreadyAccepted),
            _ => Ok(()),
        },
        Target::LotToReturn(lot_id) => match lot(&lot_id) {
            Some(l) if l.returned.is_some() => Err(StateError::LotReturned),
            _ => Ok(()),
        },
        Target::EntryToReturn(lot_id, escrow) => match lot(&lot_id) {
            Some(l) => match l.entries.iter().find(|e| e.escrow == escrow) {
                Some(e) if e.returned.is_some() => Err(StateError::EntryReturned),
                _ => Ok(()),
            },
            None => Ok(()),
        },
    }
}

/// Time-free boundary pre-check for a recipient action (harness §6): unknown
/// auction, wrong signer, a stored state that admits no action at all, or a
/// target already in the terminal shape this action would move it to.
///
/// It needs no action *kind*: with the winner arithmetic every recipient action
/// lives in `Bidding` and none survives the close, so the state half is decided
/// by the state alone; what still differs per action is the target, and that is
/// [`Target`]. Conservative on time — answered against the stored, un-advanced
/// state, and `Bidding` only ever leaves for `Done`, which admits nothing.
///
/// A strict subset of the per-action state ops' rejections, which stay
/// authoritative.
pub fn recipient_admits(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    target: Target,
) -> Result<(), StateError> {
    AUCTIONS.with_borrow(|a| {
        let s = a.get(auction_id).ok_or(StateError::NotFound)?;
        if s.recipient != *signer {
            return Err(StateError::NotRecipient);
        }
        if !s.auction.state.admits() {
            return Err(StateError::Step(StepError::InvalidTransition));
        }
        target_admits(s, target)
    })
}

/// Time-free boundary pre-check for `register_entry` — the cheap, committed-state
/// half, run **before** the threshold-resolver and PDA derivations and the
/// birth-proof walk (`cost.md §6` #2: the cheapest decisive check first).
///
/// An auction this canister has never seen is **not** a refusal: a first confirmed
/// entry is exactly what materializes one. A known auction must still be open, and
/// the lot must not have been returned — both monotone, so a refusal here is one
/// the update will still make.
///
/// This is the vector that actually mattered. A registration doomed for a reason
/// the boundary did not read — the auction closed, the lot returned — was admitted
/// and executed replicated, and since the escrow stays `Unknown` it never trips
/// `DuplicateEscrow` either. One birth-proved request, valid forever, replayed at
/// no cost to the sender, each replay buying a signature verification, a resolver
/// derivation, a PDA bump search and a hash-tree walk on every node.
pub fn register_admits(auction_id: &[u8; 32], lot_id: &[u8; 32]) -> Result<(), StateError> {
    AUCTIONS.with_borrow(|a| {
        let Some(s) = a.get(auction_id) else {
            return Ok(()); // unmaterialized — this entry may be the one that creates it
        };
        if !s.auction.state.admits() {
            return Err(StateError::Step(StepError::InvalidTransition));
        }
        match s.lots.iter().find(|l| l.lot_id == *lot_id) {
            Some(l) if l.returned.is_some() => Err(StateError::LotReturned),
            _ => Ok(()),
        }
    })
}

/// The auction's state, with the accrued close applied at `now`. Called from
/// `request_signature` (an update, where the close persists) and from the
/// read-only queries, where the mutation is discarded — harmless, because the
/// close is a pure function of a lot set that `T` has already frozen, so both
/// paths compute the same winner.
pub fn auction_state(auction_id: &[u8; 32], now: u64) -> Option<View> {
    AUCTIONS.with_borrow_mut(|a| {
        let s = a.get_mut(auction_id)?;
        let (auction, lots) = (&mut s.auction, &s.lots);
        let _ = tick(auction, now, || top_lot(lots));
        Some(view(s))
    })
}

/// The leaf scope (`entry_id`) of a confirmed entry, under which its verdict is
/// signed. `None` if the auction/lot/escrow is unknown — an unregistered escrow
/// gets no verdict and recovers on-chain via the deadline `refund`.
pub fn entry_scope(
    auction_id: &[u8; 32],
    lot_id: &[u8; 32],
    escrow: &[u8; 32],
) -> Option<[u8; 32]> {
    AUCTIONS.with_borrow(|a| {
        let s = a.get(auction_id)?;
        let lot = s.lots.iter().find(|l| l.lot_id == *lot_id)?;
        lot.entries
            .iter()
            .find(|e| e.escrow == *escrow)
            .map(|e| e.entry_id)
    })
}

/// A lot's public view: `(accepted, returned, live_entries, total, text_hash)`.
///
/// `total` is on the view because the winner is now arithmetic: a donor deciding
/// whether to top up has to be able to see the standing they are bidding against,
/// and it is the canister's own number rather than the board's reconstruction.
pub fn lot_view(
    auction_id: &[u8; 32],
    lot_id: &[u8; 32],
) -> Option<(bool, bool, u64, u128, [u8; 32])> {
    AUCTIONS.with_borrow(|a| {
        let s = a.get(auction_id)?;
        let lot = s.lots.iter().find(|l| l.lot_id == *lot_id)?;
        let live = lot.entries.iter().filter(|e| e.returned.is_none()).count() as u64;
        Some((
            lot.accepted_at.is_some(),
            lot.returned.is_some(),
            live,
            lot.total,
            lot.text_hash,
        ))
    })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const CREATED: u64 = 1_000;
    const DUR: u64 = 600;
    /// The close instant `T`.
    const T: u64 = CREATED + DUR;

    fn fresh_auction() -> Auction {
        Auction {
            state: State::Bidding,
            created_at: CREATED,
            duration: DUR,
        }
    }

    fn reset() {
        AUCTIONS.with_borrow_mut(BTreeMap::clear);
        crown_games_common::signing::reset_for_test();
    }

    // The signature store's own behaviour — repeat served free, one claim at a
    // time, an aborted signing left retriable — is tested once, in
    // `crown_games_common::signing`. Re-testing it per game re-tested one
    // mechanism three times and told us nothing about this game (`P7.6`).

    fn setup(id: [u8; 32], recipient: [u8; 32]) {
        materialize(id, fresh_auction(), recipient, 0).unwrap();
    }

    fn entry(
        id: &[u8; 32],
        lot: [u8; 32],
        text: [u8; 32],
        escrow: [u8; 32],
        gross: u64,
        now: u64,
    ) -> Result<(), StateError> {
        // A distinct leaf scope per escrow (in production `entry_id`); here the
        // escrow bytes stand in, so it is unique per entry.
        //
        // That substitution is why these tests stayed green while `entry_id` was
        // collidable: uniqueness is assumed here, not derived. The property that
        // one escrow gets one scope belongs to the derivation and is tested where
        // it lives — `protocol::twin_escrows_differing_only_in_gross_or_deadline_
        // are_distinct_scopes`. Do not "strengthen" this fixture by re-deriving
        // `entry_id`: it would re-test `protocol` and still tell us nothing about
        // `state`, which stores whatever scope it is handed.
        add_entry(id, text, lot, escrow, escrow, gross, now)
    }

    /// The winner after the close at `now`.
    fn winner(id: &[u8; 32], now: u64) -> Option<[u8; 32]> {
        match auction_state(id, now) {
            Some(View {
                state: State::Done { winner_lot },
                ..
            }) => winner_lot,
            _ => None,
        }
    }

    /// The view every still-open op returns: `Bidding`, closing at `T`. Spelled
    /// once so the assertions below stay about the auction, not about the view.
    fn open() -> View {
        View {
            state: State::Bidding,
            closes_at: T,
        }
    }

    /// The view of a closed auction with `winner_lot`.
    fn closed(winner_lot: Option<[u8; 32]>) -> View {
        View {
            state: State::Done { winner_lot },
            closes_at: T,
        }
    }

    fn total(id: &[u8; 32], lot: &[u8; 32]) -> u128 {
        lot_view(id, lot).unwrap().3
    }

    #[test]
    fn materialize_is_idempotent() {
        reset();
        let id = [1u8; 32];
        assert_eq!(materialize(id, fresh_auction(), [2; 32], 0), Ok(()));
        assert!(is_materialized(&id));
        assert_eq!(
            materialize(id, fresh_auction(), [2; 32], 0),
            Err(StateError::AlreadyExists)
        );
    }

    #[test]
    fn add_entry_creates_lots_sums_them_and_dedups_escrow() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        // First entry of lot A → lot created, total = its gross.
        assert_eq!(
            entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1),
            Ok(())
        );
        assert_eq!(total(&id, &[10; 32]), 500);
        // Top-up into lot A (same text) adds to the same total.
        assert_eq!(
            entry(&id, [10; 32], [20; 32], [31; 32], 300, CREATED + 1),
            Ok(())
        );
        assert_eq!(total(&id, &[10; 32]), 800);
        // Different lot B keeps its own total.
        assert_eq!(
            entry(&id, [11; 32], [21; 32], [32; 32], 900, CREATED + 1),
            Ok(())
        );
        assert_eq!(total(&id, &[11; 32]), 900);
        // Duplicate escrow → rejected, and it does not double-count the deposit.
        assert_eq!(
            entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1),
            Err(StateError::DuplicateEscrow)
        );
        assert_eq!(total(&id, &[10; 32]), 800);
        // At T the window shuts: registration is refused and the auction is closed.
        assert_eq!(
            entry(&id, [11; 32], [21; 32], [33; 32], 100, T),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        // Neither lot was accepted, so nobody won.
        assert_eq!(auction_state(&id, T), Some(closed(None)));
    }

    /// The rule the whole redesign exists for: at the close the heaviest accepted
    /// lot wins, and topping up is how a lot gets there.
    #[test]
    fn the_heaviest_accepted_lot_wins_the_close() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap(); // A: 500
        entry(&id, [11; 32], [21; 32], [32; 32], 900, CREATED + 1).unwrap(); // B: 900
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        accept_lot(&id, &r, &[11; 32], CREATED + 2).unwrap();
        // B leads — until two top-ups carry A past it.
        entry(&id, [10; 32], [20; 32], [33; 32], 300, CREATED + 3).unwrap(); // A: 800
        entry(&id, [10; 32], [20; 32], [34; 32], 200, CREATED + 3).unwrap(); // A: 1000
        assert_eq!(total(&id, &[10; 32]), 1_000);
        assert_eq!(winner(&id, T), Some([10u8; 32]));
    }

    /// Only lots the recipient accepted compete — an unaccepted lot cannot win no
    /// matter how heavy it is.
    #[test]
    fn an_unaccepted_lot_never_wins_however_heavy() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap(); // accepted
        entry(&id, [11; 32], [21; 32], [32; 32], 9_000, CREATED + 1).unwrap(); // never accepted
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        assert_eq!(winner(&id, T), Some([10u8; 32]));
    }

    /// A returned lot is out of the contest, and the next heaviest takes the close.
    #[test]
    fn returning_the_leader_hands_the_close_to_the_runner_up() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        entry(&id, [11; 32], [21; 32], [32; 32], 900, CREATED + 1).unwrap();
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        accept_lot(&id, &r, &[11; 32], CREATED + 2).unwrap();
        return_lot(&id, &r, &[11; 32], CREATED + 3).unwrap();
        assert_eq!(winner(&id, T), Some([10u8; 32]));
    }

    /// A returned entry stops weighing, which can flip the close.
    #[test]
    fn a_returned_entry_leaves_its_lots_total() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap(); // A: 500
        entry(&id, [10; 32], [20; 32], [31; 32], 600, CREATED + 1).unwrap(); // A: 1100
        entry(&id, [11; 32], [21; 32], [32; 32], 900, CREATED + 1).unwrap(); // B: 900
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        accept_lot(&id, &r, &[11; 32], CREATED + 2).unwrap();
        // A leads with 1100; returning its 600 drops it to 500, behind B.
        return_entry(&id, &r, &[10; 32], &[31; 32], CREATED + 3).unwrap();
        assert_eq!(total(&id, &[10; 32]), 500);
        assert_eq!(winner(&id, T), Some([11u8; 32]));
    }

    /// An accepted lot whose every entry was returned holds no money — it must not
    /// win a settle over an empty set of escrows.
    #[test]
    fn an_emptied_lot_cannot_win() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        return_entry(&id, &r, &[10; 32], &[30; 32], CREATED + 3).unwrap();
        assert_eq!(total(&id, &[10; 32]), 0);
        assert_eq!(winner(&id, T), None);
    }

    /// Ties go to the lot that opened first: a later bid must outbid, not match.
    /// Two auctions, because reading the winner closes the one it is read on —
    /// the tie and the one-unit-over case cannot share a timeline.
    #[test]
    fn a_tie_goes_to_the_lot_that_opened_first() {
        reset();
        let r = [9u8; 32];
        // `b_extra` minor units go onto the later lot B; the winner is returned.
        let close_with = |id: [u8; 32], b_extra: u64| {
            setup(id, r);
            entry(&id, [10; 32], [20; 32], [30; 32], 700, CREATED + 1).unwrap(); // A first
            entry(&id, [11; 32], [21; 32], [32; 32], 700, CREATED + 2).unwrap(); // B equal
            if b_extra > 0 {
                entry(&id, [11; 32], [21; 32], [33; 32], b_extra, CREATED + 2).unwrap();
            }
            accept_lot(&id, &r, &[10; 32], CREATED + 3).unwrap();
            accept_lot(&id, &r, &[11; 32], CREATED + 3).unwrap();
            winner(&id, T)
        };
        // Dead heat → the lot that opened first takes it.
        assert_eq!(close_with([1u8; 32], 0), Some([10u8; 32]));
        // One more minor unit on B and it takes the close outright.
        assert_eq!(close_with([2u8; 32], 1), Some([11u8; 32]));
    }

    /// The close is computed once. A first touch long after `T` must produce the
    /// same winner as one at `T` — and, once stored, must never be recomputed.
    #[test]
    fn the_close_is_fixed_and_independent_of_when_it_is_first_touched() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        // First touch a long way past T.
        assert_eq!(winner(&id, T + 100_000), Some([10u8; 32]));
        // And it stays put on every later read.
        assert_eq!(winner(&id, T + 200_000), Some([10u8; 32]));
    }

    /// Nothing the recipient does survives the close — the winner cannot be
    /// curated away after the fact.
    #[test]
    fn recipient_actions_are_refused_after_the_close() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        let doomed = Err(StateError::Step(StepError::InvalidTransition));
        assert_eq!(cancel_auction(&id, &r, T), doomed);
        assert_eq!(return_lot(&id, &r, &[10; 32], T), doomed);
        assert_eq!(return_entry(&id, &r, &[10; 32], &[30; 32], T), doomed);
        assert_eq!(accept_lot(&id, &r, &[10; 32], T), doomed);
        // The winner picked at the close is untouched.
        assert_eq!(winner(&id, T), Some([10u8; 32]));
    }

    #[test]
    fn accept_gates_recipient_state_and_double_accept() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        // Stranger cannot accept.
        assert_eq!(
            accept_lot(&id, &[8; 32], &[10; 32], CREATED + 1),
            Err(StateError::NotRecipient)
        );
        // Recipient accepts.
        assert_eq!(
            accept_lot(&id, &[9; 32], &[10; 32], CREATED + 1),
            Ok(open())
        );
        // Second accept → already accepted.
        assert_eq!(
            accept_lot(&id, &[9; 32], &[10; 32], CREATED + 1),
            Err(StateError::LotAlreadyAccepted)
        );
        // Unknown lot.
        assert_eq!(
            accept_lot(&id, &[9; 32], &[99; 32], CREATED + 1),
            Err(StateError::LotNotFound)
        );
    }

    #[test]
    fn no_topup_into_a_returned_lot() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        assert_eq!(
            return_lot(&id, &[9; 32], &[10; 32], CREATED + 2),
            Ok(open())
        );
        assert_eq!(
            entry(&id, [10; 32], [20; 32], [31; 32], 300, CREATED + 3),
            Err(StateError::LotReturned)
        );
    }

    #[test]
    fn return_entry_marks_one_escrow() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        entry(&id, [10; 32], [20; 32], [31; 32], 300, CREATED + 1).unwrap();
        assert_eq!(
            return_entry(&id, &[9; 32], &[10; 32], &[30; 32], CREATED + 2),
            Ok(open())
        );
        assert_eq!(entry_status(&id, &[10; 32], &[30; 32]), Known::Returned);
        assert_eq!(entry_status(&id, &[10; 32], &[31; 32]), Known::Live);
        // A second return of the same escrow → already returned, and the total
        // does not drop twice.
        assert_eq!(
            return_entry(&id, &[9; 32], &[10; 32], &[30; 32], CREATED + 2),
            Err(StateError::EntryReturned)
        );
        assert_eq!(total(&id, &[10; 32]), 300);
        // Unknown escrow.
        assert_eq!(
            return_entry(&id, &[9; 32], &[10; 32], &[77; 32], CREATED + 2),
            Err(StateError::EntryNotFound)
        );
    }

    #[test]
    fn cancel_from_bidding_is_done_with_no_winner() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        assert_eq!(cancel_auction(&id, &r, CREATED + 3), Ok(closed(None)));
        // A cancelled auction has no winner even though a heavy lot stood.
        assert_eq!(winner(&id, T), None);
    }

    #[test]
    fn entry_scope_is_per_entry_and_absent_for_unknowns() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        entry(&id, [10; 32], [20; 32], [31; 32], 300, CREATED + 1).unwrap();
        // Each entry has its own leaf scope (here the escrow bytes stand in).
        assert_eq!(entry_scope(&id, &[10; 32], &[30; 32]), Some([30u8; 32]));
        assert_eq!(entry_scope(&id, &[10; 32], &[31; 32]), Some([31u8; 32]));
        // Unknown escrow / lot → no scope (no verdict; refunds on-chain by deadline).
        assert_eq!(entry_scope(&id, &[10; 32], &[99; 32]), None);
        assert_eq!(entry_scope(&id, &[77; 32], &[30; 32]), None);
    }

    #[test]
    fn unmaterialized_self_signed_actions_are_not_found() {
        // A self-signed cancel/accept/return does NOT materialize an auction (only
        // a birth-proven `register` does): every one is NotFound on an unknown id
        // and writes nothing.
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        assert_eq!(cancel_auction(&id, &r, 1), Err(StateError::NotFound));
        assert_eq!(accept_lot(&id, &r, &[10; 32], 1), Err(StateError::NotFound));
        assert_eq!(return_lot(&id, &r, &[10; 32], 1), Err(StateError::NotFound));
        assert_eq!(
            return_entry(&id, &r, &[10; 32], &[30; 32], 1),
            Err(StateError::NotFound)
        );
        assert!(!is_materialized(&id));
    }

    /// The boundary must refuse a doomed recipient action, not leave it to the
    /// update — otherwise one signed `cancel` is a flood template executed
    /// replicated at the canister's expense.
    #[test]
    fn recipient_admits_refuses_what_the_state_will_refuse() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];

        assert_eq!(
            recipient_admits(&id, &recipient, Target::Auction),
            Err(StateError::NotFound)
        );

        materialize(id, fresh_auction(), recipient, 1).unwrap();
        assert_eq!(
            recipient_admits(&id, &[8u8; 32], Target::Auction),
            Err(StateError::NotRecipient)
        );
        // `Bidding` runs the auction.
        assert_eq!(recipient_admits(&id, &recipient, Target::Auction), Ok(()));

        // `Done` is absorbing: nothing at all, ever.
        cancel_auction(&id, &recipient, CREATED).unwrap();
        assert_eq!(
            recipient_admits(&id, &recipient, Target::Auction),
            Err(StateError::Step(StepError::InvalidTransition))
        );
    }

    /// A signed request carries no nonce and no expiry, so one observed
    /// `accept_lot`/`return_lot`/`return_entry` is a template anyone can resubmit
    /// forever. Once its target is already in the shape the action would produce,
    /// every replay is doomed — and must die at the boundary, not buy a replicated
    /// round each time.
    #[test]
    fn the_boundary_kills_replays_of_an_action_already_applied() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        let (a, b) = ([10u8; 32], [11u8; 32]);
        setup(id, r);
        entry(&id, a, [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        entry(&id, b, [21; 32], [32; 32], 500, CREATED + 1).unwrap();

        // Fresh targets are admitted.
        assert_eq!(recipient_admits(&id, &r, Target::LotToAccept(a)), Ok(()));
        assert_eq!(recipient_admits(&id, &r, Target::LotToReturn(b)), Ok(()));
        assert_eq!(
            recipient_admits(&id, &r, Target::EntryToReturn(a, [30; 32])),
            Ok(())
        );

        accept_lot(&id, &r, &a, CREATED + 2).unwrap();
        return_lot(&id, &r, &b, CREATED + 2).unwrap();
        return_entry(&id, &r, &a, &[30; 32], CREATED + 2).unwrap();

        // Every replay of the same signed action is now refused before execution,
        // with the very error the update would have produced.
        assert_eq!(
            recipient_admits(&id, &r, Target::LotToAccept(a)),
            Err(StateError::LotAlreadyAccepted)
        );
        assert_eq!(
            recipient_admits(&id, &r, Target::LotToReturn(b)),
            Err(StateError::LotReturned)
        );
        assert_eq!(
            recipient_admits(&id, &r, Target::EntryToReturn(a, [30; 32])),
            Err(StateError::EntryReturned)
        );
        // A returned lot can never be accepted either.
        assert_eq!(
            recipient_admits(&id, &r, Target::LotToAccept(b)),
            Err(StateError::LotReturned)
        );
    }

    /// The same for registration, and this is the vector that actually mattered: a
    /// doomed `register_entry` keeps its escrow `Unknown`, so `DuplicateEscrow`
    /// never catches the replay. Each admitted replay buys a resolver derivation,
    /// a PDA bump search and a witness walk on every node — for free.
    #[test]
    fn the_boundary_kills_replays_of_a_doomed_registration() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        let (a, b) = ([10u8; 32], [11u8; 32]);

        // An auction nobody has materialized yet is not a refusal — a first entry
        // is exactly what creates one.
        assert!(!is_materialized(&id));
        assert_eq!(register_admits(&id, &a), Ok(()));

        setup(id, r);
        entry(&id, a, [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        entry(&id, b, [21; 32], [32; 32], 500, CREATED + 1).unwrap();
        assert_eq!(register_admits(&id, &a), Ok(()));

        // Returned lot → every further registration into it is doomed, forever.
        return_lot(&id, &r, &b, CREATED + 2).unwrap();
        assert_eq!(register_admits(&id, &b), Err(StateError::LotReturned));
        assert_eq!(register_admits(&id, &a), Ok(()), "lot A is untouched");

        // Closed auction → every registration is doomed, for every lot.
        accept_lot(&id, &r, &a, CREATED + 3).unwrap();
        assert_eq!(auction_state(&id, T), Some(closed(Some(a))));
        for lot in [a, b] {
            assert_eq!(
                register_admits(&id, &lot),
                Err(StateError::Step(StepError::InvalidTransition))
            );
        }
    }

    /// Every boundary rejection must be one the update would also make, or a
    /// legitimate call is dropped for free and reads as a refusal without cause.
    /// The targets the boundary deliberately does **not** read are the ones that
    /// can appear later — an unknown lot, an unknown entry — because a
    /// registration landing in the same round makes such a call valid.
    #[test]
    fn the_boundary_never_refuses_what_the_update_would_accept() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        materialize(id, fresh_auction(), r, 1).unwrap();

        // Unknown lot / unknown entry: admitted, precisely because they are not
        // monotone. The update stays authoritative and answers LotNotFound.
        assert_eq!(
            recipient_admits(&id, &r, Target::LotToAccept([77; 32])),
            Ok(())
        );
        assert_eq!(
            recipient_admits(&id, &r, Target::EntryToReturn([77; 32], [78; 32])),
            Ok(())
        );
        assert_eq!(register_admits(&id, &[77; 32]), Ok(()));

        // And the update indeed accepts a real action the boundary admitted.
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED).unwrap();
        assert_eq!(
            recipient_admits(&id, &r, Target::LotToAccept([10; 32])),
            Ok(())
        );
        assert!(
            accept_lot(&id, &r, &[10; 32], CREATED).is_ok(),
            "update refused an action the boundary admitted"
        );
        // `return_entry` does not read the lot's `returned` flag, so the boundary
        // must not either — a strict subset, not a stricter one.
        return_lot(&id, &r, &[10; 32], CREATED).unwrap();
        assert_eq!(
            recipient_admits(&id, &r, Target::EntryToReturn([10; 32], [30; 32])),
            Ok(())
        );
        assert!(return_entry(&id, &r, &[10; 32], &[30; 32], CREATED).is_ok());
    }
}
