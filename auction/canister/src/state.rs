//! Canister state + orchestration (in-memory). A new version is a fresh canister
//! (harness §7 bars migration), so heap state is correct. Blind and registryless
//! at the escrow level: an auction holds its lots, a lot holds its confirmed
//! entries (each escrow carries its own leaf scope `resolver = key([entry_id])`,
//! so a verdict names exactly one escrow — a lot is only a contest group). The
//! machine (`auction-logic`) gates by auction state; the value/role gates live
//! here — `gross ≥ min_entry` (in `validate`), lot-not-returned, accept-not-
//! already-accepted, entry-not-returned, and pick-must-be-an-accepted-lot.
//! Host-testable pure operations under thin `ic_cdk` wrappers.

use auction_logic::{step, Action, ActionKind, Auction, Known, State, StepError, Vote};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// A confirmed contribution to a lot. The canister is blind to amounts: `gross`
/// is validated against `min_entry` at `register_entry` and then not stored — the
/// recipient sees sums on the off-canister board and picks the winner. Only the
/// fields the three-stage resolution reads are kept: `returned` (liveness),
/// `escrow` (identity/dedup), and `entry_id` — the entry's leaf scope, under which
/// its verdict is signed (`resolver = key([entry_id])`).
#[derive(Clone)]
struct StoredEntry {
    returned: Option<u64>,
    escrow: [u8; 32],
    entry_id: [u8; 32],
}

/// A lot: its contest key (`lot_id`), its `text_hash`, and the confirmed entries.
/// A lot holds no resolver — the resolver lives at the entry (its settlement leaf).
#[derive(Clone)]
struct StoredLot {
    lot_id: [u8; 32],
    text_hash: [u8; 32],
    accepted_at: Option<u64>,
    returned: Option<u64>,
    entries: Vec<StoredEntry>,
}

/// A materialized auction: the logic machine, the recipient (authorizes
/// accept/ready/return/cancel/pick), the `min_entry` snapshot, and the lots.
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

/// State-level errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    AlreadyExists,
    NotFound,
    NotRecipient,
    LotNotFound,
    LotReturned,
    LotAlreadyAccepted,
    LotNotAccepted,
    EntryNotFound,
    EntryReturned,
    DuplicateEscrow,
    VoteCapReached,
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
pub fn timing(auction_id: &[u8; 32]) -> Option<(u64, u64, u64, u64, u64)> {
    AUCTIONS.with_borrow(|a| {
        a.get(auction_id).map(|s| {
            (
                s.auction.created_at,
                s.auction.duration,
                s.auction.perform_window,
                s.auction.voting_period,
                s.min_entry,
            )
        })
    })
}

/// Add a confirmed entry to its lot (creating the lot on first sight). Gates:
/// auction still `Bidding` before `T` (the machine `RegisterEntry` step), lot not
/// returned, escrow not already present.
pub fn add_entry(
    auction_id: &[u8; 32],
    text_hash: [u8; 32],
    lot_id: [u8; 32],
    entry_id: [u8; 32],
    escrow: [u8; 32],
    now: u64,
) -> Result<(), StateError> {
    with_auction(auction_id, |s| {
        // Machine gate: register only in Bidding before `T` (advances time first).
        step(&mut s.auction, Action::RegisterEntry, now).map_err(StateError::Step)?;
        // Escrow uniqueness across the auction (a duplicate birth proof is a no-op).
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
        };
        match find_lot(s, &lot_id) {
            Some(lot) => {
                if lot.returned.is_some() {
                    return Err(StateError::LotReturned); // no top-up into a returned lot
                }
                lot.entries.push(entry);
            }
            None => s.lots.push(StoredLot {
                lot_id,
                text_hash,
                accepted_at: None,
                returned: None,
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
/// gated `Bidding` by the machine. Sets `accepted_at = now`.
pub fn accept_lot(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    lot_id: &[u8; 32],
    now: u64,
) -> Result<State, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        step(&mut s.auction, Action::AcceptLot, now).map_err(StateError::Step)?;
        let lot = find_lot(s, lot_id).ok_or(StateError::LotNotFound)?;
        if lot.returned.is_some() {
            return Err(StateError::LotReturned);
        }
        if lot.accepted_at.is_some() {
            return Err(StateError::LotAlreadyAccepted);
        }
        lot.accepted_at = Some(now);
        Ok(s.auction.state.clone())
    })
}

/// `return_lot` (recipient): non-winner in `Bidding`, or the winner in
/// `Performing` (→ `Done{Cancel}`). Marks the lot returned.
pub fn return_lot(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    lot_id: &[u8; 32],
    now: u64,
) -> Result<State, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        let is_winner = s.auction.winner_lot == Some(*lot_id);
        step(&mut s.auction, Action::ReturnLot { is_winner }, now).map_err(StateError::Step)?;
        let lot = find_lot(s, lot_id).ok_or(StateError::LotNotFound)?;
        if lot.returned.is_some() {
            return Err(StateError::LotReturned);
        }
        lot.returned = Some(now);
        Ok(s.auction.state.clone())
    })
}

/// `return_entry` (recipient): return one specific entry's escrow. Allowed on any
/// lot in `Bidding`, or the winner lot in `Performing`.
pub fn return_entry(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    lot_id: &[u8; 32],
    escrow: &[u8; 32],
    now: u64,
) -> Result<State, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        let is_winner_lot = s.auction.winner_lot == Some(*lot_id);
        step(&mut s.auction, Action::ReturnEntry { is_winner_lot }, now)
            .map_err(StateError::Step)?;
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
        Ok(s.auction.state.clone())
    })
}

/// `pick_winner` (recipient): name an accepted, non-returned lot as the winner
/// → `Performing{winner_lot}`. This is how bidding ends — there is no scan.
pub fn pick_winner(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    lot_id: &[u8; 32],
    now: u64,
) -> Result<State, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        // Only an accepted, non-returned lot may be picked.
        match s.lots.iter().find(|l| l.lot_id == *lot_id) {
            None => return Err(StateError::LotNotFound),
            Some(l) if l.returned.is_some() => return Err(StateError::LotReturned),
            Some(l) if l.accepted_at.is_none() => return Err(StateError::LotNotAccepted),
            Some(_) => {}
        }
        step(&mut s.auction, Action::PickWinner { lot_id: *lot_id }, now)
            .map_err(StateError::Step)?;
        Ok(s.auction.state.clone())
    })
}

/// `cancel_auction` (recipient): `Bidding → Done{None}`.
pub fn cancel_auction(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    now: u64,
) -> Result<State, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        step(&mut s.auction, Action::CancelAuction, now).map_err(StateError::Step)?;
        Ok(s.auction.state.clone())
    })
}

/// `ready` (recipient): `Performing → Voting{now}`.
pub fn ready(auction_id: &[u8; 32], signer: &[u8; 32], now: u64) -> Result<State, StateError> {
    with_auction(auction_id, |s| {
        require_recipient(s, signer)?;
        step(&mut s.auction, Action::Ready, now).map_err(StateError::Step)?;
        Ok(s.auction.state.clone())
    })
}

/// Time-free boundary pre-check for a vote: the cheap committed-state reasons a
/// vote is doomed — unknown auction, over cap, duplicate voter, or the stored
/// state is not `Voting`. Run in `admit_vote` *before* the weight proof so a
/// replayed/valid-proof-but-doomed vote dies at the boundary without a BLS
/// pairing, instead of re-verifying on the replicated path (harness §6). It is a
/// strict subset of `add_vote`'s rejections — a vote `add_vote` would accept is
/// on a materialized, `Voting`, under-cap, non-duplicate auction, so all four
/// checks pass here; `add_vote` stays the authoritative gate (it advances time
/// and mutates). The stored state suffices: `Voting` is only ever left for
/// `Done` by time, never entered, so an effective `Voting` implies a stored one.
pub fn vote_admits(
    auction_id: &[u8; 32],
    voter: &[u8; 32],
    v_max: usize,
) -> Result<(), StateError> {
    AUCTIONS.with_borrow(|a| {
        let s = a.get(auction_id).ok_or(StateError::NotFound)?;
        if s.auction.votes.len() >= v_max {
            return Err(StateError::VoteCapReached);
        }
        if s.auction.votes.iter().any(|e| e.voter == *voter) {
            return Err(StateError::Step(StepError::DuplicateVoter));
        }
        if !matches!(s.auction.state, State::Voting { .. }) {
            return Err(StateError::Step(StepError::InvalidTransition));
        }
        Ok(())
    })
}

/// Record a weight-proven vote on the (winner) lot: gated `Voting`, dedup +
/// threshold in the machine, capped `V_MAX`.
pub fn add_vote(
    auction_id: &[u8; 32],
    vote: Vote,
    now: u64,
    v_max: usize,
) -> Result<State, StateError> {
    with_auction(auction_id, |s| {
        if s.auction.votes.len() >= v_max {
            return Err(StateError::VoteCapReached);
        }
        step(&mut s.auction, Action::Vote(vote), now).map_err(StateError::Step)?;
        Ok(s.auction.state.clone())
    })
}

/// The recipient-picked winner lot, or `None` before `pick_winner`.
pub fn winner_lot(auction_id: &[u8; 32]) -> Option<[u8; 32]> {
    AUCTIONS.with_borrow(|a| a.get(auction_id)?.auction.winner_lot)
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

/// The auction's recipient (for weight-proof keying).
pub fn recipient(auction_id: &[u8; 32]) -> Option<[u8; 32]> {
    AUCTIONS.with_borrow(|a| a.get(auction_id).map(|s| s.recipient))
}

/// Time-free boundary pre-check for a recipient action (harness §6), the twin of
/// [`vote_admits`]: unknown auction, wrong signer, or a stored state that admits
/// no action of this kind.
///
/// Takes an [`ActionKind`], not an `Action`: `return_lot`/`return_entry` carry a
/// winner flag this canister reads from stored state, and the boundary must not
/// guess it — a kind is admitted if *some* flag would be. Together with the
/// time-free reading that makes the check conservative on both axes, which is
/// what `State::admits` documents and an exhaustive machine test pins.
///
/// A strict subset of the per-action state ops' rejections, which stay
/// authoritative. Without it the boundary passed every action from the right
/// signer, and the doomed ones were executed replicated at the canister's
/// expense — free for the sender, and unbounded, since the signed half of a
/// request carries no nonce and replays.
pub fn action_admits(
    auction_id: &[u8; 32],
    signer: &[u8; 32],
    kind: ActionKind,
) -> Result<(), StateError> {
    AUCTIONS.with_borrow(|a| {
        let s = a.get(auction_id).ok_or(StateError::NotFound)?;
        if s.recipient != *signer {
            return Err(StateError::NotRecipient);
        }
        if !s.auction.state.admits(kind) {
            return Err(StateError::Step(StepError::InvalidTransition));
        }
        Ok(())
    })
}

/// The auction's state, with accrued time transitions applied at `now`.
pub fn auction_state(auction_id: &[u8; 32], now: u64) -> Option<State> {
    AUCTIONS.with_borrow_mut(|a| {
        let s = a.get_mut(auction_id)?;
        let _ = step(&mut s.auction, Action::Tick, now);
        Some(s.auction.state.clone())
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

/// A lot's public view: `(accepted, returned, live_entries, text_hash)`.
pub fn lot_view(auction_id: &[u8; 32], lot_id: &[u8; 32]) -> Option<(bool, bool, u64, [u8; 32])> {
    AUCTIONS.with_borrow(|a| {
        let s = a.get(auction_id)?;
        let lot = s.lots.iter().find(|l| l.lot_id == *lot_id)?;
        let live = lot.entries.iter().filter(|e| e.returned.is_none()).count() as u64;
        Some((
            lot.accepted_at.is_some(),
            lot.returned.is_some(),
            live,
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
    const PW: u64 = 300;
    const VP: u64 = 120;

    fn fresh_auction() -> Auction {
        Auction {
            state: State::Bidding,
            created_at: CREATED,
            duration: DUR,
            perform_window: PW,
            voting_period: VP,
            winner_lot: None,
            votes: Vec::new(),
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
        _gross: u64, // the canister is blind to amounts; kept to document the bid
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
        add_entry(id, text, lot, escrow, escrow, now)
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
    fn add_entry_creates_lots_and_dedups_escrow() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        // First entry of lot A → lot created.
        assert_eq!(
            entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1),
            Ok(())
        );
        // Top-up into lot A (same text).
        assert_eq!(
            entry(&id, [10; 32], [20; 32], [31; 32], 300, CREATED + 1),
            Ok(())
        );
        // Different lot B.
        assert_eq!(
            entry(&id, [11; 32], [21; 32], [32; 32], 900, CREATED + 1),
            Ok(())
        );
        // Duplicate escrow → rejected (no double count).
        assert_eq!(
            entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1),
            Err(StateError::DuplicateEscrow)
        );
        // After T → register frozen; the state stays Bidding (no auto-transition).
        assert_eq!(
            entry(&id, [11; 32], [21; 32], [33; 32], 100, CREATED + DUR),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        assert_eq!(auction_state(&id, CREATED + DUR), Some(State::Bidding));
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
            Ok(State::Bidding)
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
        // Recipient returns the (non-winner) lot in Bidding.
        assert_eq!(
            return_lot(&id, &[9; 32], &[10; 32], CREATED + 2),
            Ok(State::Bidding)
        );
        // A top-up into the returned lot is refused (reviewer caveat).
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
            Ok(State::Bidding)
        );
        // Second return of the same escrow → already returned.
        assert_eq!(
            return_entry(&id, &[9; 32], &[10; 32], &[30; 32], CREATED + 2),
            Err(StateError::EntryReturned)
        );
        // Unknown escrow.
        assert_eq!(
            return_entry(&id, &[9; 32], &[10; 32], &[77; 32], CREATED + 2),
            Err(StateError::EntryNotFound)
        );
    }

    #[test]
    fn cancel_from_bidding_is_done_none() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        assert_eq!(
            cancel_auction(&id, &[9; 32], CREATED + 1),
            Ok(State::Done { winner: None })
        );
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
    fn pick_winner_opens_performing_and_gates() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap(); // lot A
        entry(&id, [11; 32], [21; 32], [32; 32], 900, CREATED + 1).unwrap(); // lot B
        accept_lot(&id, &[9; 32], &[10; 32], CREATED + 2).unwrap(); // accept A only

        // Stranger cannot pick.
        assert_eq!(
            pick_winner(&id, &[8; 32], &[10; 32], CREATED + 3),
            Err(StateError::NotRecipient)
        );
        // Unaccepted lot B cannot be picked.
        assert_eq!(
            pick_winner(&id, &[9; 32], &[11; 32], CREATED + 3),
            Err(StateError::LotNotAccepted)
        );
        // Unknown lot.
        assert_eq!(
            pick_winner(&id, &[9; 32], &[99; 32], CREATED + 3),
            Err(StateError::LotNotFound)
        );
        // Picking the accepted lot A → Performing, winner fixed.
        assert_eq!(
            pick_winner(&id, &[9; 32], &[10; 32], CREATED + 3),
            Ok(State::Performing)
        );
        assert_eq!(winner_lot(&id), Some([10u8; 32]));
        // A second pick (now Performing) → invalid.
        assert_eq!(
            pick_winner(&id, &[9; 32], &[10; 32], CREATED + 4),
            Err(StateError::Step(StepError::InvalidTransition))
        );
    }

    #[test]
    fn a_returned_lot_cannot_be_picked() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        accept_lot(&id, &[9; 32], &[10; 32], CREATED + 2).unwrap();
        return_lot(&id, &[9; 32], &[10; 32], CREATED + 3).unwrap();
        assert_eq!(
            pick_winner(&id, &[9; 32], &[10; 32], CREATED + 4),
            Err(StateError::LotReturned)
        );
    }

    #[test]
    fn pick_after_bidding_close_still_works() {
        reset();
        let id = [1u8; 32];
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        accept_lot(&id, &[9; 32], &[10; 32], CREATED + 2).unwrap();
        // Registration is frozen after T, but picking is still open (state Bidding).
        assert_eq!(auction_state(&id, CREATED + DUR + 5), Some(State::Bidding));
        assert_eq!(
            pick_winner(&id, &[9; 32], &[10; 32], CREATED + DUR + 5),
            Ok(State::Performing)
        );
    }

    fn mkvote(v: u8) -> Vote {
        Vote {
            voter: [v; 32],
            weight: 200_000, // ≥ MIN_VOTE_WEIGHT (100_000)
            done: true,
        }
    }

    /// Materialize → one accepted lot → picked → ready, leaving the auction in
    /// `Voting{started_at: CREATED+4}` with recipient `[9;32]`.
    fn to_voting(id: [u8; 32]) {
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        accept_lot(&id, &[9; 32], &[10; 32], CREATED + 2).unwrap();
        pick_winner(&id, &[9; 32], &[10; 32], CREATED + 3).unwrap();
        ready(&id, &[9; 32], CREATED + 4).unwrap();
    }

    #[test]
    fn unmaterialized_self_signed_actions_are_not_found() {
        // A self-signed ready/cancel/pick/accept/return/vote does NOT materialize an
        // auction (only a birth-proven `register` does): every one is NotFound on an
        // unknown id and writes nothing.
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        assert_eq!(ready(&id, &r, 1), Err(StateError::NotFound));
        assert_eq!(cancel_auction(&id, &r, 1), Err(StateError::NotFound));
        assert_eq!(
            pick_winner(&id, &r, &[10; 32], 1),
            Err(StateError::NotFound)
        );
        assert_eq!(accept_lot(&id, &r, &[10; 32], 1), Err(StateError::NotFound));
        assert_eq!(return_lot(&id, &r, &[10; 32], 1), Err(StateError::NotFound));
        assert_eq!(
            return_entry(&id, &r, &[10; 32], &[30; 32], 1),
            Err(StateError::NotFound)
        );
        assert_eq!(add_vote(&id, mkvote(1), 1, 500), Err(StateError::NotFound));
        assert!(!is_materialized(&id));
    }

    #[test]
    fn winner_lot_return_and_entry_return_in_performing() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap(); // lot A → winner
        entry(&id, [11; 32], [21; 32], [32; 32], 900, CREATED + 1).unwrap(); // lot B → loser
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        assert_eq!(
            pick_winner(&id, &r, &[10; 32], CREATED + 3),
            Ok(State::Performing)
        );
        // return_entry on the winner lot is allowed in Performing (marks one escrow).
        assert_eq!(
            return_entry(&id, &r, &[10; 32], &[30; 32], CREATED + 4),
            Ok(State::Performing)
        );
        assert_eq!(entry_status(&id, &[10; 32], &[30; 32]), Known::Returned);
        // return_entry on a NON-winner lot in Performing is rejected (loser lot is
        // already auto-cancelled — only the winner lot may be touched).
        assert_eq!(
            return_entry(&id, &r, &[11; 32], &[32; 32], CREATED + 4),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        // The recipient may return the winner lot in Performing → Done{Cancel}.
        assert_eq!(
            return_lot(&id, &r, &[10; 32], CREATED + 5),
            Ok(State::Done {
                winner: Some(auction_logic::Outcome::Cancel)
            })
        );
    }

    #[test]
    fn ready_gates_bidding_and_add_vote_requires_voting() {
        reset();
        let id = [1u8; 32];
        let r = [9u8; 32];
        setup(id, r);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        accept_lot(&id, &r, &[10; 32], CREATED + 2).unwrap();
        // `ready` is invalid while still Bidding (not yet picked).
        assert_eq!(
            ready(&id, &r, CREATED + 2),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        // Pick → Performing; a vote before `ready` (not yet Voting) is invalid.
        pick_winner(&id, &r, &[10; 32], CREATED + 3).unwrap();
        assert_eq!(
            add_vote(&id, mkvote(1), CREATED + 3, 500),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        // `ready` → Voting.
        assert_eq!(
            ready(&id, &r, CREATED + 4),
            Ok(State::Voting {
                started_at: CREATED + 4
            })
        );
    }

    #[test]
    fn add_vote_caps_at_v_max_and_wires_the_threshold() {
        reset();
        let id = [1u8; 32];
        to_voting(id);
        let voting = State::Voting {
            started_at: CREATED + 4,
        };
        // Cap of 2: two distinct votes land; the third is refused before the machine.
        assert_eq!(add_vote(&id, mkvote(1), CREATED + 5, 2), Ok(voting.clone()));
        assert_eq!(add_vote(&id, mkvote(2), CREATED + 5, 2), Ok(voting));
        assert_eq!(
            add_vote(&id, mkvote(3), CREATED + 5, 2),
            Err(StateError::VoteCapReached)
        );
        // Below-threshold weight is refused (wiring to the machine's threshold),
        // even under a high cap.
        let weak = Vote {
            voter: [4; 32],
            weight: 1,
            done: true,
        };
        assert_eq!(
            add_vote(&id, weak, CREATED + 5, 500),
            Err(StateError::Step(StepError::WeightBelowThreshold))
        );
    }

    /// The boundary must refuse a doomed recipient action, not leave it to the
    /// update — otherwise one signed `ready` (or `cancel`, or `pick`) is a flood
    /// template executed replicated at the canister's expense.
    #[test]
    fn action_admits_refuses_what_the_state_will_refuse() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];

        assert_eq!(
            action_admits(&id, &recipient, ActionKind::Ready),
            Err(StateError::NotFound)
        );

        materialize(id, fresh_auction(), recipient, 1).unwrap();
        assert_eq!(
            action_admits(&id, &[8u8; 32], ActionKind::CancelAuction),
            Err(StateError::NotRecipient)
        );

        // `Bidding` runs the auction but has no `ready` and no vote.
        for k in [
            ActionKind::AcceptLot,
            ActionKind::ReturnLot,
            ActionKind::ReturnEntry,
            ActionKind::PickWinner,
            ActionKind::CancelAuction,
        ] {
            assert_eq!(
                action_admits(&id, &recipient, k),
                Ok(()),
                "{k:?} in Bidding"
            );
        }
        for k in [ActionKind::Ready, ActionKind::Vote] {
            assert_eq!(
                action_admits(&id, &recipient, k),
                Err(StateError::Step(StepError::InvalidTransition)),
                "{k:?} must be refused while Bidding"
            );
        }

        // `Done` is absorbing: nothing at all, ever.
        cancel_auction(&id, &recipient, CREATED).unwrap();
        for k in [
            ActionKind::AcceptLot,
            ActionKind::ReturnLot,
            ActionKind::ReturnEntry,
            ActionKind::PickWinner,
            ActionKind::CancelAuction,
            ActionKind::Ready,
            ActionKind::Vote,
        ] {
            assert_eq!(
                action_admits(&id, &recipient, k),
                Err(StateError::Step(StepError::InvalidTransition)),
                "{k:?} must be refused on a done auction"
            );
        }
    }

    /// Every boundary rejection must be one the update would also make, or a
    /// legitimate call is dropped for free and reads as a refusal without cause.
    /// `ready` is the interesting one: doomed in `Bidding`, live in `Performing`.
    #[test]
    fn action_admits_never_refuses_what_the_update_would_accept() {
        reset();
        let id = [1u8; 32];
        let recipient = [9u8; 32];
        let lot = [3u8; 32];
        materialize(id, fresh_auction(), recipient, 1).unwrap();

        assert_eq!(
            action_admits(&id, &recipient, ActionKind::PickWinner),
            Ok(())
        );
        // A lot must exist and be accepted before it can win; drive the auction
        // through the real ops so the states are the ones the update produces.
        accept_lot(&id, &recipient, &lot, CREATED).ok();
        if pick_winner(&id, &recipient, &lot, CREATED).is_ok() {
            // Now `Performing`: `ready` becomes admissible and applicable.
            assert_eq!(action_admits(&id, &recipient, ActionKind::Ready), Ok(()));
            assert!(
                ready(&id, &recipient, CREATED).is_ok(),
                "update refused `ready` the boundary admitted"
            );
        }
    }

    #[test]
    fn vote_admits_is_a_subset_of_add_vote_and_needs_no_weight_proof() {
        reset();
        let id = [1u8; 32];
        // Unknown auction → NotFound (the boundary drops it before any BLS).
        assert_eq!(vote_admits(&id, &[1; 32], 500), Err(StateError::NotFound));
        // Materialized but still Bidding (not Voting) → InvalidTransition.
        setup(id, [9; 32]);
        entry(&id, [10; 32], [20; 32], [30; 32], 500, CREATED + 1).unwrap();
        assert_eq!(
            vote_admits(&id, &[1; 32], 500),
            Err(StateError::Step(StepError::InvalidTransition))
        );
        // Drive to Voting: a fresh voter with room is admitted.
        accept_lot(&id, &[9; 32], &[10; 32], CREATED + 2).unwrap();
        pick_winner(&id, &[9; 32], &[10; 32], CREATED + 3).unwrap();
        ready(&id, &[9; 32], CREATED + 4).unwrap();
        assert_eq!(vote_admits(&id, &[1; 32], 500), Ok(()));
        // Record it → a replay of the same voter is DuplicateVoter (no BLS re-run).
        add_vote(&id, mkvote(1), CREATED + 5, 500).unwrap();
        assert_eq!(
            vote_admits(&id, &[1; 32], 500),
            Err(StateError::Step(StepError::DuplicateVoter))
        );
        // Cap is checked before the duplicate scan (matching add_vote's order).
        assert_eq!(
            vote_admits(&id, &[2; 32], 1),
            Err(StateError::VoteCapReached)
        );
    }
}
