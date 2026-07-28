//! auction canister — a lot auction on the `two-outcome` form. Blind: bids are
//! confirmed by a birth proof (not chain reads); the canister is blind to amounts.
//! A lot is a contest group; a contribution is the settlement unit
//! (`resolver = key([entry_id])`).
//!
//! `create_auction` is a pure derivation echo (zero writes, permissionless).
//! `register_entry` (donor-signed) is the materialization carrier: it verifies the
//! contribution's birth at the derived escrow, materializes the auction on the
//! first confirmed entry (fixing `created_at`), and adds the entry to its lot.
//! The recipient runs the auction — `accept_lot`/`return_lot`/`return_entry`/
//! `pick_winner`/`cancel_auction`/`ready` — all signature-gated by the recipient.
//! There is no on-chain winner scan: the recipient names the winner (`pick_winner`).
//! `vote` (winner lot) and `request_signature` (per-entry verdict) settle it.

use auction_logic::{
    resolve, Auction, Known, Outcome, Resolution, State, Vote, LOGIC_VERSION, MIN_VOTE_WEIGHT,
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
pub use crown_games_common::{address, birth, bs58_array, request, resolver};

thread_local! {
    /// Cached threshold master (public key + chain code); entry resolvers derive from it.
    static MASTER: RefCell<Option<([u8; 32], [u8; 32])>> = const { RefCell::new(None) };
    /// crown-indexer principal (birth proofs are keyed to it).
    static INDEX: RefCell<Principal> = const { RefCell::new(Principal::anonymous()) };
    /// NNS root key that authenticates the index's certificate (blind proof).
    static NNS_ROOT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// IC mainnet root key — finalized at P8 (the pinned NNS BLS key; fill from the
/// official published value, never a guessed constant). On testnet it is supplied
/// via `init`. Empty fails every birth proof closed (safe), and on the mainnet
/// profile `init` traps rather than ship a dead trust anchor (mirrors the
/// `genesis_unix == 0` build guard).
const IC_MAINNET_ROOT_KEY: &[u8] = &[];

/// Cap of votes per auction (non-negativity invariant #7).
const V_MAX: usize = 500;

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

/// Outcome of an update — flat and typed.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum AuctionResult {
    // success
    Materialized,
    Registered,
    Derived { auction: String },
    Advanced(AuctionStateView),
    KeyBootstrapped,
    Signed { outcome: u8, signature: Vec<u8> },
    // wiring / request
    Malformed,
    WrongTarget,
    NotBootstrapped,
    AuctionIdMismatch,
    BadBirthProof,
    FieldMismatch,
    CreatedAtOverflow,
    Underpaid,  // attached cycles below SIGN_PRICE
    NotDecided, // no verdict yet (no charge)
    SignFailed, // sign_with_schnorr rejected
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
            if config::PROFILE == "mainnet" && IC_MAINNET_ROOT_KEY.is_empty() {
                ic_cdk::trap("IC_MAINNET_ROOT_KEY is unset (P8: pin the NNS root key before mainnet)");
            }
            INDEX.with_borrow_mut(|i| *i = index);
            NNS_ROOT.with_borrow_mut(|k| *k = IC_MAINNET_ROOT_KEY.to_vec());
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

// ---- Updates ----

/// Pure derivation echo (recipient-signed, zero writes, permissionless): the
/// boundary-shared `admit_create` recomputes `auction_id` and confirms it matches
/// the signed `auction`; here we just echo the derived id. Materialization happens
/// later, on the first confirmed entry (`register_entry`).
#[ic_cdk::update]
fn create_auction(text: String) -> AuctionResult {
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
            r.min_entry,
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
        if let Err(e) = validate::validate_entry(r.gross, floor, r.deadline, created_at, dur, pw, vp)
        {
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

/// Largest ingress arg accepted. A legitimate signed request — even a birth
/// proof carrying a hex `cert` + `witness` — is a few KB; this leaves ample
/// headroom while dropping a multi-MB flood before it can force parsing, hex
/// decoding, or (on the vote path) BLS verification. Mirrors the relay's guard.
const MAX_ARG_BYTES: usize = 32 * 1024;

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
    if ic_cdk::api::msg_cycles_available() < config::SIGN_PRICE {
        return AuctionResult::Underpaid;
    }
    if chain != config::CHAIN_ID {
        return AuctionResult::WrongTarget;
    }
    let (Some(auction_id), Some(lot_id), Some(escrow)) =
        (hex32(&auction), hex32(&lot), bs58_array::<32>(&escrow))
    else {
        return AuctionResult::Malformed;
    };
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
                Ok(res) => AuctionResult::Signed {
                    outcome,
                    signature: res.signature,
                },
                Err(_) => AuctionResult::SignFailed,
            }
        }
    }
}

// ---- Queries ----

#[ic_cdk::query]
fn get_logic_version() -> u32 {
    LOGIC_VERSION
}

/// The resolver a donor bakes into their escrow for entry `(lot, donor, nonce)`:
/// `key([entry_id])`, `entry_id = sha256(lot ‖ donor ‖ nonce)`. Per-entry, so the
/// verdict signed under it settles only this one escrow. Free, pure derivation.
#[ic_cdk::query]
fn get_resolver(lot: String, donor: String, nonce: u64) -> Option<String> {
    let lot_id = hex32(&lot)?;
    let donor = bs58_array::<32>(&donor)?;
    let entry_id = protocol::entry_id(&lot_id, &donor, nonce);
    let (pk, cc) = MASTER.with_borrow(|m| *m)?;
    resolver::resolver(&pk, &cc, &entry_id).map(|r| bs58::encode(r).into_string())
}

#[ic_cdk::query]
fn get_auction(auction: String) -> Option<AuctionStateView> {
    let id = hex32(&auction)?;
    state::auction_state(&id, now_secs()).map(|s| state_view(&s))
}

#[ic_cdk::query]
fn get_lot(auction: String, lot: String) -> Option<LotView> {
    let (id, lot_id) = (hex32(&auction)?, hex32(&lot)?);
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
/// the book witness against the certified index root. `None` if the proof is
/// invalid or the auction is unknown.
fn voter_weight(req: &request::Request, auction_id: &[u8; 32], voter: &[u8; 32]) -> Option<u128> {
    let recipient = state::recipient(auction_id)?;
    let cert = hex_vec(req.extra("cert"))?;
    let weight_witness = hex_vec(req.extra("weight_witness"))?;
    let index = INDEX.with_borrow(|i| *i);
    let root_key = NNS_ROOT.with_borrow(|k| k.clone());
    let combined_root = birth::certified_root(&cert, &root_key, index.as_slice())?;
    birth::reputation_from_witness(
        &weight_witness,
        &combined_root,
        &chain_id_hash(),
        voter,
        &recipient,
    )
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
        req.signed("auction").and_then(hex32),
        parse_u64(req.signed("duration")),
        parse_u64(req.signed("perform_window")),
        parse_u64(req.signed("voting_period")),
        parse_u64(req.signed("min_entry")),
        parse_u64(req.extra("recipient_nonce")),
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
        req.signed("auction").and_then(hex32),
        req.signed("text").and_then(hex32),
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
        parse_u64(req.extra("recipient_nonce")),
        parse_u64(req.extra("duration")),
        parse_u64(req.extra("perform_window")),
        parse_u64(req.extra("voting_period")),
        parse_u64(req.extra("min_entry")),
    )
    else {
        return Err(AuctionResult::Malformed);
    };
    let (Some(gross), Some(deadline), Some(nonce), Some(cert), Some(witness)) = (
        parse_u64(req.extra("gross")),
        parse_i64(req.extra("deadline")),
        parse_u64(req.extra("nonce")),
        hex_vec(req.extra("cert")),
        hex_vec(req.extra("witness")),
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
    let entry_id = protocol::entry_id(&lot_id, &donor, nonce);
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
    let index = INDEX.with_borrow(|i| *i);
    let root_key = NNS_ROOT.with_borrow(|k| k.clone());
    let Some(combined_root) = birth::certified_root(&cert, &root_key, index.as_slice()) else {
        return Err(AuctionResult::BadBirthProof);
    };
    let Some(b) = birth::birth_from_witness(&witness, &combined_root, &escrow) else {
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
fn admit_lot_action(text: &str, action_name: &str) -> Result<LotAdmit, AuctionResult> {
    let Some(req) = request::parse(text) else {
        return Err(AuctionResult::Malformed);
    };
    if req.signed("action") != Some(action_name) || !target_ok(&req) {
        return Err(AuctionResult::WrongTarget);
    }
    let (Some(auction_id), Some(lot_id)) = (
        req.signed("auction").and_then(hex32),
        req.signed("lot").and_then(hex32),
    ) else {
        return Err(AuctionResult::Malformed);
    };
    match state::recipient(&auction_id) {
        Some(r) if r == req.pubkey => Ok((auction_id, req.pubkey, lot_id)),
        Some(_) => Err(AuctionResult::NotRecipient),
        None => Err(AuctionResult::NotFound),
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
    let Some(auction_id) = req.signed("auction").and_then(hex32) else {
        return Err(AuctionResult::Malformed);
    };
    match state::recipient(&auction_id) {
        Some(r) if r == req.pubkey => Ok((auction_id, req.pubkey)),
        Some(_) => Err(AuctionResult::NotRecipient),
        None => Err(AuctionResult::NotFound),
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
        req.signed("auction").and_then(hex32),
        req.signed("lot").and_then(hex32),
        req.signed("entry").and_then(bs58_array::<32>),
    ) else {
        return Err(AuctionResult::Malformed);
    };
    match state::recipient(&auction_id) {
        Some(r) if r == req.pubkey => Ok((auction_id, req.pubkey, lot_id, escrow)),
        Some(_) => Err(AuctionResult::NotRecipient),
        None => Err(AuctionResult::NotFound),
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
        req.signed("auction").and_then(hex32),
        req.signed("lot").and_then(hex32),
        req.signed("choice").and_then(parse_choice),
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
        "create_auction" => admit_create(text).is_ok(),
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

fn parse_choice(c: &str) -> Option<bool> {
    match c {
        "done" => Some(true),
        "not_done" => Some(false),
        _ => None,
    }
}

/// `ChainId` as the index keys the book: `sha256("crown-chain:v1:" ‖ id)`.
fn chain_id_hash() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"crown-chain:v1:");
    h.update(config::CHAIN_ID.as_bytes());
    h.finalize().into()
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

fn parse_u64(s: Option<&str>) -> Option<u64> {
    s?.parse().ok()
}
fn parse_i64(s: Option<&str>) -> Option<i64> {
    s?.parse().ok()
}
fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}
fn hex_vec(s: Option<&str>) -> Option<Vec<u8>> {
    hex::decode(s?).ok()
}

ic_cdk::export_candid!();
