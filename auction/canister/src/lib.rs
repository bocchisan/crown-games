//! auction canister — a lot auction on the `two-outcome` form. Blind: bids are
//! confirmed by a birth proof (not chain reads); the canister is blind to amounts.
//! A lot is a contest group; a contribution is the settlement unit
//! (`resolver = key([entry_id])`).
//!
//! `get_auction_id` is a pure derivation echo (zero writes, permissionless) and a
//! `query` — as an `update` it was replicated free work on the anonymous path.
//! `register_entry` (donor-signed) is the materialization carrier: it verifies the
//! contribution's birth at the derived escrow, materializes the auction on the
//! first confirmed entry (fixing `created_at`), and adds the entry to its lot.
//! The recipient runs the auction — `accept_lot`/`return_lot`/`return_entry`/
//! `pick_winner`/`cancel_auction`/`ready` — all signature-gated by the recipient.
//! There is no on-chain winner scan: the recipient names the winner (`pick_winner`).
//! `vote` (winner lot) and `request_signature` (per-entry verdict) settle it.

use auction_logic::{
    resolve, ActionKind, Auction, Known, Outcome, Resolution, State, Vote, LOGIC_VERSION,
    MIN_VOTE_WEIGHT,
};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk_management_canister::{
    schnorr_public_key, sign_with_schnorr, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SignWithSchnorrArgs,
};
use std::cell::RefCell;

pub mod config;
pub mod protocol;
pub mod state;
pub mod validate;

// The delicate, game-agnostic crypto (birth/reputation proof, threshold resolver
// derivation, escrow-address PDA, wallet signature, request framing) lives in
// `crown-games-common`. Re-exported to keep call sites uniform across every game.
pub use crown_games_common::{
    address, birth, bs58_array, field, request, resolver, roots, signing, MAX_ARG_BYTES, V_MAX,
};

thread_local! {
    /// Cached threshold master (public key + chain code); entry resolvers derive from it.
    static MASTER: RefCell<Option<([u8; 32], [u8; 32])>> = const { RefCell::new(None) };
    /// crown-indexer principal (birth proofs are keyed to it).
    static INDEX: RefCell<Principal> = const { RefCell::new(Principal::anonymous()) };
    /// NNS root key that authenticates the index's certificate (blind proof).
    static NNS_ROOT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// Recently verified index roots (newest last). A birth/reputation witness is
    /// admitted against any of them; the BLS that authenticates a root runs once,
    /// on the paid `push_root`, never on the anonymous boundary. Canister state,
    /// so it lives here; the cache policy is `roots` (one copy for every game).
    static ROOTS: RefCell<Vec<[u8; 32]>> = const { RefCell::new(Vec::new()) };
}

/// Deploy-time overrides (testnet). Barred on mainnet.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    pub index: Principal,
    pub nns_root_key: Vec<u8>,
}

/// An auction's state, for `get_auction` / `Advanced`.
#[derive(CandidType, Deserialize, Clone, Copy, Debug)]
pub enum AuctionStateView {
    Bidding,
    Performing,
    Voting,
    DoneSettle,
    DoneCancel,
    DoneNoWinner,
}

/// A lot's public view.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct LotView {
    pub accepted: bool,
    pub returned: bool,
    pub live_entries: u64,
    pub text_hash: String,
}

/// A produced verdict signature, for `get_signature`.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SignatureView {
    pub outcome: u8,
    pub signature: Vec<u8>,
}

/// Outcome of an update — flat and typed.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum AuctionResult {
    // success
    Materialized,
    Registered,
    Derived {
        auction: String,
    },
    Advanced(AuctionStateView),
    KeyBootstrapped,
    Signed {
        outcome: u8,
        signature: Vec<u8>,
    },
    /// A certified index root was authenticated and cached.
    RootPushed,
    // wiring / request
    Malformed,
    WrongTarget,
    NotBootstrapped,
    AuctionIdMismatch,
    BadBirthProof,
    FieldMismatch,
    CreatedAtOverflow,
    Underpaid,  // attached cycles below SIGN_PRICE / ROOT_PRICE
    NotDecided, // no verdict yet (no charge)
    SignFailed, // sign_with_schnorr rejected
    /// A sibling call is already signing this entry scope — free, no charge.
    /// Retry and the produced signature is served from store.
    SignInFlight,
    // registration validation
    GrossBelowMinEntry,
    DurationOutOfRange,
    PerformWindowOutOfRange,
    VotingPeriodOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
    // state
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
    // step
    InvalidTransition,
    WeightBelowThreshold,
    DuplicateVoter,
    StepOverflow,
}

#[ic_cdk::init]
fn init(overrides: Option<InitArgs>) {
    match overrides {
        Some(a) => {
            if config::PROFILE == "mainnet" {
                ic_cdk::trap("init override is barred on mainnet");
            }
            INDEX.with_borrow_mut(|i| *i = a.index);
            NNS_ROOT.with_borrow_mut(|k| *k = a.nns_root_key);
        }
        None => {
            let index = Principal::from_text(config::CROWN_INDEX)
                .unwrap_or_else(|_| ic_cdk::trap("baked index principal is invalid"));
            INDEX.with_borrow_mut(|i| *i = index);
            NNS_ROOT.with_borrow_mut(|k| *k = crown_games_common::IC_MAINNET_ROOT_KEY.to_vec());
        }
    }
}

/// One-time idempotent fetch of the threshold master public key.
#[ic_cdk::update]
async fn bootstrap() -> AuctionResult {
    if MASTER.with_borrow(|m| m.is_some()) {
        return AuctionResult::KeyBootstrapped;
    }
    let arg = SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: vec![],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: config::THRESHOLD_KEY.to_string(),
        },
    };
    let Ok(res) = schnorr_public_key(&arg).await else {
        return AuctionResult::Malformed;
    };
    let (Ok(pk), Ok(cc)) = (
        <[u8; 32]>::try_from(res.public_key),
        <[u8; 32]>::try_from(res.chain_code),
    ) else {
        return AuctionResult::Malformed;
    };
    MASTER.with_borrow_mut(|m| *m = Some((pk, cc)));
    AuctionResult::KeyBootstrapped
}

/// Pure derivation echo (recipient-signed, zero writes, permissionless):
/// `admit_create` recomputes `auction_id` and confirms it matches the signed
/// `auction`; here we just echo the derived id. Materialization happens later, on
/// the first confirmed entry (`register_entry`).
///
/// A `query`, and that is the whole point (`P7.15`, spec §Таблица переходов ¹).
/// It reads no mutable state and writes none, so as an `update` it made the
/// entire subnet recompute — replicated, at this canister's expense — what one
/// node can compute. Worse, it was the one state-changing entry point whose
/// admissibility depended on nothing external: a fresh keypair signs its own
/// message and `auction_id` recomputes from its own fields, so the boundary
/// admitted it *always*. No dedup, no cap, no cost to the caller. The reference
/// game has no such method at all — `task_id` is derived client-side and the
/// first touch is already a birth-proved `register_task`.
#[ic_cdk::query]
fn get_auction_id(text: String) -> AuctionResult {
    match admit_create(&text) {
        Ok(id) => AuctionResult::Derived {
            auction: hex::encode(id),
        },
        Err(e) => e,
    }
}

/// Materialization carrier (donor-signed): the boundary-shared `admit_register_entry`
/// verifies the contribution's birth at the derived escrow (the time-free prefix,
/// run at the boundary and re-run here authoritatively); this body performs only
/// the time/state-dependent tail — materialize on the first confirmed entry (fixing
/// `created_at`), gate the entry against the fixed timeline, and add it to its lot.
#[ic_cdk::update]
fn register_entry(text: String) -> AuctionResult {
    let r = match admit_register_entry(&text) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // First confirmed entry materializes the auction (fixing created_at from the
    // birth slot). Time/state-dependent, so it stays out of the time-free boundary.
    let materialized_now = !state::is_materialized(&r.auction_id);
    if materialized_now {
        // Validate EVERYTHING that could reject the first entry BEFORE committing
        // `materialize` — a rejected first entry must not leave a zombie auction
        // (materialized, zero live entries, and idempotent → never re-materializable).
        if let Err(e) = validate::validate_ranges(r.duration, r.perform_window, r.voting_period) {
            return reg_error(e);
        }
        let Some(created_at) = config::slot_to_created_at(r.birth.slot) else {
            return AuctionResult::CreatedAtOverflow;
        };
        if let Err(e) = validate::validate_entry(
            r.gross,
            validate::entry_floor(r.min_entry, config::MIN_ENTRY),
            r.deadline,
            created_at,
            r.duration,
            r.perform_window,
            r.voting_period,
        ) {
            return reg_error(e);
        }
        // Registration must be open at the fixed timeline (mirror of the machine's
        // `RegisterEntry` gate `now < created_at + duration`); otherwise `add_entry`
        // would reject *after* the commit and brick the auction.
        let Some(bidding_end) = created_at.checked_add(r.duration) else {
            return AuctionResult::TimeOverflow;
        };
        if now_secs() >= bidding_end {
            return AuctionResult::InvalidTransition;
        }
        let auction = Auction {
            state: State::Bidding,
            created_at,
            duration: r.duration,
            perform_window: r.perform_window,
            voting_period: r.voting_period,
            winner_lot: None,
            votes: Vec::new(),
        };
        // Now nothing below can fail on a fresh auction: window open + not-tight are
        // proven, and a fresh auction has no duplicate/returned to hit.
        if let Err(e) = state::materialize(r.auction_id, auction, r.recipient, r.min_entry) {
            return state_error(e);
        }
    } else {
        // Top-up into an existing auction: gate against its fixed created_at. A
        // closed window just rejects the top-up in `add_entry` — no zombie, the
        // auction already exists.
        let Some((created_at, dur, pw, vp, floor)) = state::timing(&r.auction_id) else {
            return AuctionResult::NotFound;
        };
        if let Err(e) = validate::validate_entry(
            r.gross,
            validate::entry_floor(floor, config::MIN_ENTRY),
            r.deadline,
            created_at,
            dur,
            pw,
            vp,
        ) {
            return reg_error(e);
        }
    }

    match state::add_entry(
        &r.auction_id,
        r.text_hash,
        r.lot_id,
        r.entry_id,
        r.escrow,
        now_secs(),
    ) {
        Ok(()) if materialized_now => AuctionResult::Materialized,
        Ok(()) => AuctionResult::Registered,
        Err(e) => state_error(e),
    }
}

#[ic_cdk::update]
fn accept_lot(text: String) -> AuctionResult {
    lot_action(&text, "accept", |auction_id, signer, lot_id, now| {
        state::accept_lot(auction_id, signer, lot_id, now)
    })
}

#[ic_cdk::update]
fn return_lot(text: String) -> AuctionResult {
    lot_action(&text, "return_lot", |auction_id, signer, lot_id, now| {
        state::return_lot(auction_id, signer, lot_id, now)
    })
}

#[ic_cdk::update]
fn return_entry(text: String) -> AuctionResult {
    let (auction_id, signer, lot_id, escrow) = match admit_return_entry(&text) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match state::return_entry(&auction_id, &signer, &lot_id, &escrow, now_secs()) {
        Ok(s) => AuctionResult::Advanced(state_view(&s)),
        Err(e) => state_error(e),
    }
}

/// The recipient names the winning lot (accepted, non-returned) → `Performing`.
#[ic_cdk::update]
fn pick_winner(text: String) -> AuctionResult {
    lot_action(&text, "pick", |auction_id, signer, lot_id, now| {
        state::pick_winner(auction_id, signer, lot_id, now)
    })
}

#[ic_cdk::update]
fn cancel_auction(text: String) -> AuctionResult {
    auction_action(&text, "cancel", |auction_id, signer, now| {
        state::cancel_auction(auction_id, signer, now)
    })
}

#[ic_cdk::update]
fn ready(text: String) -> AuctionResult {
    auction_action(&text, "ready", |auction_id, signer, now| {
        state::ready(auction_id, signer, now)
    })
}

/// A reputation-weighted vote on the winner lot (`Voting`). Validity (signature +
/// weight proof ≥ `MIN_VOTE_WEIGHT`) is gated at the boundary via `admit_vote`; here
/// the same check runs authoritatively, then the dedup + `V_MAX` cap apply in the
/// machine/state. Weight = the voter's reputation to the auction's recipient.
#[ic_cdk::update]
fn vote(text: String) -> AuctionResult {
    let (auction_id, v) = match admit_vote(&text) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match state::add_vote(&auction_id, v, now_secs(), V_MAX) {
        Ok(s) => AuctionResult::Advanced(state_view(&s)),
        Err(e) => state_error(e),
    }
}

/// The boundary (non-negativity invariant #2, harness §6): a state-changing ingress
/// is admitted only if it would pass — its `admit_*` check (signature + target +
/// applicability proof) holds. Doomed/spam work never reaches the replicated
/// `update`, which re-checks authoritatively. Oversized args are dropped first, for
/// every method.
#[ic_cdk::inspect_message]
fn inspect_message() {
    if ic_cdk::api::msg_arg_data().len() > MAX_ARG_BYTES {
        return; // oversized ingress → dropped before execution, for free
    }
    let method = ic_cdk::api::msg_method_name();
    // `bootstrap` carries no `text` and is a one-shot fetch — admit only until the
    // master key lands, so a repeat is dropped for free.
    if method == "bootstrap" {
        if MASTER.with_borrow(|m| m.is_none()) {
            ic_cdk::api::accept_message();
        }
        return;
    }
    // Every state-changing method takes a signed `text`. `request_signature` is
    // relay-fronted (inter-canister, never inspected); a direct unpaid ingress
    // neither decodes as one `text` nor is admissible, so it is dropped.
    let Ok(text) = candid::decode_one::<String>(&ic_cdk::api::msg_arg_data()) else {
        return; // malformed / non-text args → reject
    };
    if admissible(&method, &text) {
        ic_cdk::api::accept_message();
    }
}

/// Paid pull (fronted by the relay for `ROOT_PRICE`): authenticate a fresh index
/// root and cache it, so the anonymous boundary can admit birth/reputation
/// witnesses with a hash-tree walk alone.
///
/// The certificate costs two BLS pairings (the index's signature plus the subnet
/// delegation) — far past the 200M-instruction budget of `inspect_message`, so it
/// cannot live there; and free on `update` it would be a replicated pairing for
/// any anonymous byte string. Charging it makes the one expensive step the paid
/// one and keeps every per-caller path cheap (`cost.md §6` #2).
///
/// Payment is accepted **before** the pairings, and a bogus certificate is not
/// refunded: fund-then-fail must not be cheaper than the work it triggers
/// (`01-standards §Тесты 4`).
#[ic_cdk::update]
fn push_root(cert: Vec<u8>) -> AuctionResult {
    if ic_cdk::api::msg_cycles_available() < config::ROOT_PRICE {
        return AuctionResult::Underpaid;
    }
    ic_cdk::api::msg_cycles_accept(config::ROOT_PRICE);

    let index = INDEX.with_borrow(|i| *i);
    let root_key = NNS_ROOT.with_borrow(|k| k.clone());
    let Some(root) = birth::certified_root(&cert, &root_key, index.as_slice()) else {
        return AuctionResult::BadBirthProof;
    };
    ROOTS.with_borrow_mut(|cache| roots::remember(cache, root));
    AuctionResult::RootPushed
}

/// Paid pull: the three-stage resolution → one signature under the escrow's own
/// leaf scope (`key([entry_id])`). In `Bidding` (winner not yet picked) there is
/// no verdict and no charge; `NoVerdict` (winner in `Performing`/`Voting`) also
/// refuses without charge. Payment is accepted only when there is a verdict,
/// before `sign_with_schnorr`.
#[ic_cdk::update]
async fn request_signature(
    chain: String,
    auction: String,
    lot: String,
    escrow: String,
) -> AuctionResult {
    if chain != config::CHAIN_ID {
        return AuctionResult::WrongTarget;
    }
    let (Some(auction_id), Some(lot_id), Some(escrow)) = (
        field::hex32(&auction),
        field::hex32(&lot),
        bs58_array::<32>(&escrow),
    ) else {
        return AuctionResult::Malformed;
    };
    // An entry that was already signed is served **free** — the threshold
    // signature is deterministic in `(entry_scope, outcome)` and the outcome is
    // immutable once resolved (harness §8), so re-signing would buy the same
    // bytes twice. A pure read, ahead of the payment check on purpose: a repeat
    // costs one lookup, so it is never worth charging for. Mirrors the index
    // serving a duplicate ingest (`crown-indexer/src/gate.rs`).
    if let Some((outcome, signature)) =
        state::entry_scope(&auction_id, &lot_id, &escrow).and_then(|scope| signing::cached(&scope))
    {
        return AuctionResult::Signed { outcome, signature };
    }
    if ic_cdk::api::msg_cycles_available() < config::SIGN_PRICE {
        return AuctionResult::Underpaid;
    }
    let now = now_secs();
    let Some(st) = state::auction_state(&auction_id, now) else {
        return AuctionResult::NotFound;
    };
    match st {
        // Winner not yet picked → no verdict, no charge.
        State::Bidding => AuctionResult::NotDecided,
        // The three-stage resolution → one signature over the outcome, per entry.
        State::Performing | State::Voting { .. } | State::Done { .. } => {
            let entry = state::entry_status(&auction_id, &lot_id, &escrow);
            let lot_status = state::lot_status(&auction_id, &lot_id);
            let is_winner = state::winner_lot(&auction_id) == Some(lot_id);
            let outcome = match resolve(entry, lot_status, is_winner, &st) {
                Resolution::Settle => 0u8,
                Resolution::Cancel => 1u8,
                Resolution::NoVerdict => return AuctionResult::NotDecided, // no charge
            };
            // Sign under the entry's own leaf scope so the verdict names exactly
            // this escrow — a settle for one entry can never claim a sibling that
            // should cancel. An unregistered escrow has no scope here and recovers
            // on-chain via the deadline refund (no charge).
            let Some(entry_scope) = state::entry_scope(&auction_id, &lot_id, &escrow) else {
                return AuctionResult::EntryNotFound;
            };
            // Claim the scope *before* the await: the store only lands after it,
            // so without this N concurrent requests for one entry would each miss
            // the store and each pay. A losing sibling is free — it retries and
            // finds the stored signature.
            if !signing::claim(entry_scope) {
                return AuctionResult::SignInFlight;
            }
            // Payment accepted only now, before the (paid) threshold signature.
            ic_cdk::api::msg_cycles_accept(config::SIGN_PRICE);
            let arg = SignWithSchnorrArgs {
                message: protocol::verdict_message(config::DOMAIN, &config::FACTORY, outcome),
                derivation_path: vec![entry_scope.to_vec()],
                key_id: SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Ed25519,
                    name: config::THRESHOLD_KEY.to_string(),
                },
                aux: None,
            };
            match sign_with_schnorr(&arg).await {
                Ok(res) => {
                    signing::store(entry_scope, outcome, res.signature.clone());
                    AuctionResult::Signed {
                        outcome,
                        signature: res.signature,
                    }
                }
                Err(_) => {
                    signing::release(&entry_scope); // keep the entry retriable
                    AuctionResult::SignFailed
                }
            }
        }
    }
}

// ---- Queries ----

#[ic_cdk::query]
fn get_logic_version() -> u32 {
    LOGIC_VERSION
}

/// The resolver a donor bakes into their escrow for entry
/// `(lot, donor, nonce, gross, deadline)`: `key([entry_id])`. Per-entry, so the
/// verdict signed under it settles only this one escrow. Free, pure derivation.
///
/// `gross`/`deadline` are arguments because the scope commits them (`protocol`):
/// they are the fields the escrow address derives from, and a resolver that
/// ignored them would be shared by every escrow a donor funds under one nonce.
/// The donor already knows both — they are the escrow they are about to create.
#[ic_cdk::query]
fn get_resolver(
    lot: String,
    donor: String,
    nonce: u64,
    gross: u64,
    deadline: i64,
) -> Option<String> {
    let lot_id = field::hex32(&lot)?;
    let donor = bs58_array::<32>(&donor)?;
    let entry_id = protocol::entry_id(&lot_id, &donor, nonce, gross, deadline);
    let (pk, cc) = MASTER.with_borrow(|m| *m)?;
    resolver::resolver(&pk, &cc, &entry_id).map(|r| bs58::encode(r).into_string())
}

/// The verdict signature already produced for an entry, if any. Free query — a
/// claimer that lost the race, or one that simply needs the bytes again, reads
/// them here instead of paying the relay to re-request a `SIGN_PRICE` pull.
#[ic_cdk::query]
fn get_signature(auction: String, lot: String, escrow: String) -> Option<SignatureView> {
    let (auction_id, lot_id) = (field::hex32(&auction)?, field::hex32(&lot)?);
    let escrow = bs58_array::<32>(&escrow)?;
    let scope = state::entry_scope(&auction_id, &lot_id, &escrow)?;
    let (outcome, signature) = signing::cached(&scope)?;
    Some(SignatureView { outcome, signature })
}

#[ic_cdk::query]
fn get_auction(auction: String) -> Option<AuctionStateView> {
    let id = field::hex32(&auction)?;
    state::auction_state(&id, now_secs()).map(|s| state_view(&s))
}

#[ic_cdk::query]
fn get_lot(auction: String, lot: String) -> Option<LotView> {
    let (id, lot_id) = (field::hex32(&auction)?, field::hex32(&lot)?);
    let (accepted, returned, live_entries, text_hash) = state::lot_view(&id, &lot_id)?;
    Some(LotView {
        accepted,
        returned,
        live_entries,
        text_hash: hex::encode(text_hash),
    })
}

// ---- helpers ----

fn auction_id_of(
    recipient: [u8; 32],
    recipient_nonce: u64,
    duration: u64,
    perform_window: u64,
    voting_period: u64,
    min_entry: u64,
) -> [u8; 32] {
    let canister = ic_cdk::api::canister_self();
    protocol::auction_id(
        canister.as_slice(),
        recipient,
        recipient_nonce,
        duration,
        perform_window,
        voting_period,
        min_entry,
    )
}

/// A lot-scoped recipient action (`accept` / `return_lot` / `pick`): admit it
/// (signature + target + ids + signer is the recipient) at the boundary-shared
/// `admit_lot_action`, then run `op` for the state transition.
fn lot_action(
    text: &str,
    action_name: &str,
    op: impl FnOnce(&[u8; 32], &[u8; 32], &[u8; 32], u64) -> Result<State, state::StateError>,
) -> AuctionResult {
    let (auction_id, signer, lot_id) = match admit_lot_action(text, action_name) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match op(&auction_id, &signer, &lot_id, now_secs()) {
        Ok(s) => AuctionResult::Advanced(state_view(&s)),
        Err(e) => state_error(e),
    }
}

/// An auction-scoped recipient action (`ready` / `cancel`): admit it (signature +
/// target + auction id + signer is the recipient) at the boundary-shared
/// `admit_auction_action`, then run `op` for the state transition.
fn auction_action(
    text: &str,
    action_name: &str,
    op: impl FnOnce(&[u8; 32], &[u8; 32], u64) -> Result<State, state::StateError>,
) -> AuctionResult {
    let (auction_id, signer) = match admit_auction_action(text, action_name) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match op(&auction_id, &signer, now_secs()) {
        Ok(s) => AuctionResult::Advanced(state_view(&s)),
        Err(e) => state_error(e),
    }
}

/// The voter's weight = their reputation to the auction's recipient, proven by
/// the book witness against an already-authenticated index root. `None` if the
/// proof is invalid or the auction is unknown.
///
/// Like the birth proof, this is a pure hash-tree walk against the `ROOTS` cache
/// (`push_root` did the BLS, paid). The certificate must not be verified here:
/// `admit_vote` runs at the boundary, and two pairings per anonymous vote would
/// blow the 200M-instruction `inspect_message` budget — a *valid* vote could not
/// be admitted at all (spec §Методы, `cost.md §6` #2).
fn voter_weight(req: &request::Request, auction_id: &[u8; 32], voter: &[u8; 32]) -> Option<u128> {
    let recipient = state::recipient(auction_id)?;
    let weight_witness = field::hex_bytes(req.extra("weight_witness"))?;
    let chain = crown_games_common::chain_id(config::CHAIN_ID);
    ROOTS.with_borrow(|cache| roots::reputation(cache, &weight_witness, &chain, voter, &recipient))
}

// ---- Boundary admissibility (harness §6) ----
//
// Each state-changing method has an `admit_*` that proves it would pass — the cheap
// validity prefix (signature + target + ids + signer-is-recipient), plus, for
// `register_entry`, the expensive blind birth proof, and for `vote`, the weight
// proof. The boundary (`inspect_message`) runs it to drop doomed/spam work before
// the replicated `update`; the `update` calls the same `admit_*` so the check is
// authoritative and never duplicated. Every `admit_*` is time-free (never
// `now_secs`), so it is safe to run in `inspect_message`; the time/state-dependent
// tail (materialize, deadline policy, state transition) stays in the update body.

/// Admit a `create`: signature + target + the recomputed `auction_id` matches the
/// signed `auction`. Returns the derived id; the update just echoes it.
fn admit_create(text: &str) -> Result<[u8; 32], AuctionResult> {
    let Some(req) = request::parse(text) else {
        return Err(AuctionResult::Malformed);
    };
    if req.signed("action") != Some("create") || !target_ok(&req) {
        return Err(AuctionResult::WrongTarget);
    }
    let recipient = req.pubkey;
    let (
        Some(auction_claimed),
        Some(duration),
        Some(perform_window),
        Some(voting_period),
        Some(min_entry),
        Some(recipient_nonce),
    ) = (
        req.signed("auction").and_then(field::hex32),
        field::u64_of(req.signed("duration")),
        field::u64_of(req.signed("perform_window")),
        field::u64_of(req.signed("voting_period")),
        field::u64_of(req.signed("min_entry")),
        field::u64_of(req.extra("recipient_nonce")),
    )
    else {
        return Err(AuctionResult::Malformed);
    };
    let id = auction_id_of(
        recipient,
        recipient_nonce,
        duration,
        perform_window,
        voting_period,
        min_entry,
    );
    if id != auction_claimed {
        return Err(AuctionResult::AuctionIdMismatch);
    }
    Ok(id)
}

/// A `register_entry` that passed every proof/field check — the data the update
/// needs for the time/state-dependent tail (materialize + per-entry gate + add).
/// `birth` is carried because the update reads `birth.slot` to fix `created_at`.
struct Registered {
    auction_id: [u8; 32],
    recipient: [u8; 32],
    min_entry: u64,
    duration: u64,
    perform_window: u64,
    voting_period: u64,
    gross: u64,
    deadline: i64,
    text_hash: [u8; 32],
    lot_id: [u8; 32],
    entry_id: [u8; 32],
    escrow: [u8; 32],
    birth: birth::Birth,
}

/// Admit a `register_entry`: bootstrap + signature + target + fields + `auction_id`
/// recompute (pinned by the signed `auction`) + the blind birth proof (BLS vs NNS
/// root → witness → birth), field-matched (`b.donor`; `gross` bound via address). Stops before the
/// first time/state-dependent step, so it is safe to run at the boundary. `Err`
/// carries the exact `AuctionResult` the update returns at that point.
fn admit_register_entry(text: &str) -> Result<Registered, AuctionResult> {
    let Some((master_pk, chain_code)) = MASTER.with_borrow(|m| *m) else {
        return Err(AuctionResult::NotBootstrapped);
    };
    let Some(req) = request::parse(text) else {
        return Err(AuctionResult::Malformed);
    };
    if req.signed("action") != Some("register") || !target_ok(&req) {
        return Err(AuctionResult::WrongTarget);
    }
    let donor = req.pubkey;
    let (Some(auction_claimed), Some(text_hash)) = (
        req.signed("auction").and_then(field::hex32),
        req.signed("text").and_then(field::hex32),
    ) else {
        return Err(AuctionResult::Malformed);
    };
    let (
        Some(recipient),
        Some(recipient_nonce),
        Some(duration),
        Some(perform_window),
        Some(voting_period),
        Some(min_entry),
    ) = (
        req.extra("recipient").and_then(bs58_array::<32>),
        field::u64_of(req.extra("recipient_nonce")),
        field::u64_of(req.extra("duration")),
        field::u64_of(req.extra("perform_window")),
        field::u64_of(req.extra("voting_period")),
        field::u64_of(req.extra("min_entry")),
    )
    else {
        return Err(AuctionResult::Malformed);
    };
    // Only the witness is needed: the root it reconstructs against was
    // authenticated earlier, on the paid `push_root` (no `cert` on this path).
    let (Some(gross), Some(deadline), Some(nonce), Some(witness)) = (
        field::u64_of(req.extra("gross")),
        field::i64_of(req.extra("deadline")),
        field::u64_of(req.extra("nonce")),
        field::hex_bytes(req.extra("witness")),
    ) else {
        return Err(AuctionResult::Malformed);
    };

    // Recompute auction_id from the presented fields; the signed `auction` pins it.
    let auction_id = auction_id_of(
        recipient,
        recipient_nonce,
        duration,
        perform_window,
        voting_period,
        min_entry,
    );
    if auction_id != auction_claimed {
        return Err(AuctionResult::AuctionIdMismatch);
    }

    // lot_id (contest) → entry_id (settlement leaf) → resolver → escrow address,
    // then verify the birth proof there. The resolver lives at the entry, so the
    // verdict signed under it names exactly this escrow — never a sibling.
    let lot_id = protocol::lot_id(&auction_id, &text_hash);
    let entry_id = protocol::entry_id(&lot_id, &donor, nonce, gross, deadline);
    let Some(entry_resolver) = resolver::resolver(&master_pk, &chain_code, &entry_id) else {
        return Err(AuctionResult::Malformed);
    };
    let Some(escrow) = address::escrow_address(
        config::FACTORY,
        donor,
        recipient,
        gross,
        deadline,
        entry_resolver,
        config::FEE_BPS,
        config::FEE_WALLET,
        nonce,
    ) else {
        return Err(AuctionResult::BadBirthProof);
    };
    // If this escrow is already a known entry, the registration is a duplicate
    // no-op — drop it here, before the BLS birth proof, so a replay can't force
    // the pairing on the replicated path (harness §6). `add_entry` re-checks
    // (`DuplicateEscrow`) authoritatively; a fresh escrow (`Unknown`) proceeds.
    if state::is_materialized(&auction_id)
        && state::entry_status(&auction_id, &lot_id, &escrow) != Known::Unknown
    {
        return Err(AuctionResult::DuplicateEscrow);
    }
    // Blind birth proof, boundary half: the witness is reconstructed against an
    // already-authenticated index root (`push_root` did the BLS, paid). A pure
    // hash-tree walk, O(log n) — it fits the `inspect_message` budget, which the
    // certificate's pairings do not (`push_root`).
    let Some((_, b)) = ROOTS.with_borrow(|cache| roots::birth(cache, &witness, &escrow)) else {
        return Err(AuctionResult::BadBirthProof);
    };
    // `gross` is committed via the escrow address, so the birth leaf no longer
    // carries it; only the leaf's `donor` is cross-checked here.
    if b.donor != donor {
        return Err(AuctionResult::FieldMismatch);
    }

    Ok(Registered {
        auction_id,
        recipient,
        min_entry,
        duration,
        perform_window,
        voting_period,
        gross,
        deadline,
        text_hash,
        lot_id,
        entry_id,
        escrow,
        birth: b,
    })
}

/// The admitted identifiers of a lot action: `(auction_id, signer, lot_id)`.
type LotAdmit = ([u8; 32], [u8; 32], [u8; 32]);
/// The admitted identifiers of a return-entry: `(auction_id, signer, lot_id, escrow)`.
type EntryAdmit = ([u8; 32], [u8; 32], [u8; 32], [u8; 32]);

/// Admit a lot-scoped recipient action (`accept` / `return_lot` / `pick`):
/// signature + target + ids + the signer is the auction's recipient. Returns
/// `(auction_id, signer, lot_id)`; the state op is authoritative on the transition.
/// An unknown auction is `NotFound`, a non-recipient signer is `NotRecipient` —
/// the same variants the state op used to produce.
/// The signed `action` field ↔ the machine's action kind, in **one** place. Both
/// the boundary and the update reach the state check through here, so they cannot
/// disagree about which kind a method is — a mismatch would either admit a doomed
/// call or drop a valid one, and both are silent. `None` is unreachable from the
/// fixed call sites and is treated as a wrong target rather than a panic.
fn kind_of(action_name: &str) -> Option<ActionKind> {
    Some(match action_name {
        "accept" => ActionKind::AcceptLot,
        "return_lot" => ActionKind::ReturnLot,
        "pick" => ActionKind::PickWinner,
        "cancel" => ActionKind::CancelAuction,
        "ready" => ActionKind::Ready,
        "return_entry" => ActionKind::ReturnEntry,
        _ => return None,
    })
}

fn admit_lot_action(text: &str, action_name: &str) -> Result<LotAdmit, AuctionResult> {
    let Some(req) = request::parse(text) else {
        return Err(AuctionResult::Malformed);
    };
    if req.signed("action") != Some(action_name) || !target_ok(&req) {
        return Err(AuctionResult::WrongTarget);
    }
    let (Some(auction_id), Some(lot_id)) = (
        req.signed("auction").and_then(field::hex32),
        req.signed("lot").and_then(field::hex32),
    ) else {
        return Err(AuctionResult::Malformed);
    };
    let Some(kind) = kind_of(action_name) else {
        return Err(AuctionResult::WrongTarget);
    };
    match state::action_admits(&auction_id, &req.pubkey, kind) {
        Ok(()) => Ok((auction_id, req.pubkey, lot_id)),
        Err(e) => Err(state_error(e)),
    }
}

/// Admit an auction-scoped recipient action (`ready` / `cancel`): signature +
/// target + auction id + the signer is the recipient. Returns `(auction_id, signer)`.
fn admit_auction_action(
    text: &str,
    action_name: &str,
) -> Result<([u8; 32], [u8; 32]), AuctionResult> {
    let Some(req) = request::parse(text) else {
        return Err(AuctionResult::Malformed);
    };
    if req.signed("action") != Some(action_name) || !target_ok(&req) {
        return Err(AuctionResult::WrongTarget);
    }
    let Some(auction_id) = req.signed("auction").and_then(field::hex32) else {
        return Err(AuctionResult::Malformed);
    };
    let Some(kind) = kind_of(action_name) else {
        return Err(AuctionResult::WrongTarget);
    };
    match state::action_admits(&auction_id, &req.pubkey, kind) {
        Ok(()) => Ok((auction_id, req.pubkey)),
        Err(e) => Err(state_error(e)),
    }
}

/// Admit a `return_entry`: signature + target + ids + the signer is the recipient.
/// Returns `(auction_id, signer, lot_id, escrow)`; the state op is authoritative on
/// entry liveness (`EntryNotFound` / `EntryReturned`) and the transition.
fn admit_return_entry(text: &str) -> Result<EntryAdmit, AuctionResult> {
    let Some(req) = request::parse(text) else {
        return Err(AuctionResult::Malformed);
    };
    if req.signed("action") != Some("return_entry") || !target_ok(&req) {
        return Err(AuctionResult::WrongTarget);
    }
    let (Some(auction_id), Some(lot_id), Some(escrow)) = (
        req.signed("auction").and_then(field::hex32),
        req.signed("lot").and_then(field::hex32),
        req.signed("entry").and_then(bs58_array::<32>),
    ) else {
        return Err(AuctionResult::Malformed);
    };
    match state::action_admits(&auction_id, &req.pubkey, ActionKind::ReturnEntry) {
        Ok(()) => Ok((auction_id, req.pubkey, lot_id, escrow)),
        Err(e) => Err(state_error(e)),
    }
}

/// Admit a `vote`: signature + target + a weight proof meeting `MIN_VOTE_WEIGHT`.
/// The `lot` is still decoded (a malformed lot fails the message) then discarded —
/// votes attach to the auction's winner lot, dedup is by voter. Returns
/// `(auction_id, vote)`; `state::add_vote` applies the dedup + `V_MAX` cap.
fn admit_vote(text: &str) -> Result<([u8; 32], Vote), AuctionResult> {
    let Some(req) = request::parse(text) else {
        return Err(AuctionResult::Malformed);
    };
    if req.signed("action") != Some("vote") || !target_ok(&req) {
        return Err(AuctionResult::WrongTarget);
    }
    let (Some(auction_id), Some(lot_id), Some(done)) = (
        req.signed("auction").and_then(field::hex32),
        req.signed("lot").and_then(field::hex32),
        req.signed("choice").and_then(field::choice),
    ) else {
        return Err(AuctionResult::Malformed);
    };
    let _ = lot_id; // votes attach to the auction (winner lot); dedup is by voter
                    // Cheap committed-state gate *before* the weight proof (harness §6): a doomed
                    // vote (unknown / over cap / duplicate voter / not `Voting`) is dropped here —
                    // at the boundary and without a BLS pairing — so a replay can't force the
                    // pairing on the replicated path. `add_vote` re-checks authoritatively.
    if let Err(e) = state::vote_admits(&auction_id, &req.pubkey, V_MAX) {
        return Err(state_error(e));
    }
    let Some(weight) = voter_weight(&req, &auction_id, &req.pubkey) else {
        return Err(AuctionResult::BadBirthProof);
    };
    if weight < MIN_VOTE_WEIGHT {
        return Err(AuctionResult::WeightBelowThreshold);
    }
    Ok((
        auction_id,
        Vote {
            voter: req.pubkey,
            weight,
            done,
        },
    ))
}

/// The boundary dispatch: admit a state-changing ingress iff its `admit_*` check
/// passes. `is_ok()` collapses the typed verdict to accept/drop. `request_signature`
/// is relay-fronted (inter-canister, never inspected), so as a direct ingress it
/// falls through to `_ => false` and is dropped.
fn admissible(method: &str, text: &str) -> bool {
    match method {
        // `get_auction_id` is a `query` (`P7.15`) — queries reached as queries are
        // never inspected, and reached as replicated updates they would be, which
        // is exactly the anonymous free-work path this list must not open.
        "register_entry" => admit_register_entry(text).is_ok(),
        "accept_lot" => admit_lot_action(text, "accept").is_ok(),
        "return_lot" => admit_lot_action(text, "return_lot").is_ok(),
        "pick_winner" => admit_lot_action(text, "pick").is_ok(),
        "return_entry" => admit_return_entry(text).is_ok(),
        "cancel_auction" => admit_auction_action(text, "cancel").is_ok(),
        "ready" => admit_auction_action(text, "ready").is_ok(),
        "vote" => admit_vote(text).is_ok(),
        _ => false,
    }
}

fn target_ok(req: &request::Request) -> bool {
    req.signed("canister") == Some(ic_cdk::api::canister_self().to_text().as_str())
        && req.signed("chain") == Some(config::CHAIN_ID)
}

fn now_secs() -> u64 {
    ic_cdk::api::time() / 1_000_000_000
}

fn state_view(s: &State) -> AuctionStateView {
    match s {
        State::Bidding => AuctionStateView::Bidding,
        State::Performing => AuctionStateView::Performing,
        State::Voting { .. } => AuctionStateView::Voting,
        State::Done {
            winner: Some(Outcome::Settle),
        } => AuctionStateView::DoneSettle,
        State::Done {
            winner: Some(Outcome::Cancel),
        } => AuctionStateView::DoneCancel,
        State::Done { winner: None } => AuctionStateView::DoneNoWinner,
    }
}

fn reg_error(e: validate::RegError) -> AuctionResult {
    use validate::RegError as E;
    match e {
        E::GrossBelowMinEntry => AuctionResult::GrossBelowMinEntry,
        E::DurationOutOfRange => AuctionResult::DurationOutOfRange,
        E::PerformWindowOutOfRange => AuctionResult::PerformWindowOutOfRange,
        E::VotingPeriodOutOfRange => AuctionResult::VotingPeriodOutOfRange,
        E::DeadlineTooTight => AuctionResult::DeadlineTooTight,
        E::TimeOverflow => AuctionResult::TimeOverflow,
    }
}

fn state_error(e: state::StateError) -> AuctionResult {
    use auction_logic::StepError as Se;
    use state::StateError as E;
    match e {
        E::AlreadyExists => AuctionResult::AlreadyExists,
        E::NotFound => AuctionResult::NotFound,
        E::NotRecipient => AuctionResult::NotRecipient,
        E::LotNotFound => AuctionResult::LotNotFound,
        E::LotReturned => AuctionResult::LotReturned,
        E::LotAlreadyAccepted => AuctionResult::LotAlreadyAccepted,
        E::LotNotAccepted => AuctionResult::LotNotAccepted,
        E::EntryNotFound => AuctionResult::EntryNotFound,
        E::EntryReturned => AuctionResult::EntryReturned,
        E::DuplicateEscrow => AuctionResult::DuplicateEscrow,
        E::VoteCapReached => AuctionResult::VoteCapReached,
        E::Step(Se::InvalidTransition) => AuctionResult::InvalidTransition,
        E::Step(Se::WeightBelowThreshold) => AuctionResult::WeightBelowThreshold,
        E::Step(Se::DuplicateVoter) => AuctionResult::DuplicateVoter,
        E::Step(Se::Overflow) => AuctionResult::StepOverflow,
    }
}

ic_cdk::export_candid!();
