//! conditional-funding canister — a crowdfunding collection on the `two-outcome`
//! form. Blind and registryless: escrow membership is by the `resolver` field
//! (derivation), not a list. Area = collection, `B=N`; one verdict signature is
//! reused by all `N` escrows (F4).
//!
//! F2: lazy creation. `create_collection` derives `collection_id` + resolver and,
//! given a birth proof of the first funded contribution, materializes the
//! collection (fixing `created_at` from the birth slot) — without a proof it
//! writes nothing. `ready`/`recipient_cancel` are free, self-signed, and never
//! materialize. Voting (F3) and the paid verdict pull (F4) land at their stages.

use candid::{CandidType, Deserialize, Principal};
use conditional_funding_logic::{Collection, Outcome, State, Vote, LOGIC_VERSION, MIN_VOTE_WEIGHT};
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
// derivation, escrow-address PDA, wallet signature) lives in one place —
// `crown-games-common`. Re-exported to keep `birth::`/`address::`/`resolver::`/
// `request::` call sites uniform across every game.
pub use crown_games_common::{address, birth, bs58_array, request, resolver};

thread_local! {
    /// Cached threshold master (public key + chain code); resolvers derive from it.
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

/// Cap of votes per collection (non-negativity invariant #7; cost.md §6 `V_MAX`).
const V_MAX: usize = 500;

/// Deploy-time overrides (testnet): the index principal and the NNS root key
/// (PocketIC / a test IC differ from mainnet). Barred on mainnet.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    pub index: Principal,
    pub nns_root_key: Vec<u8>,
}

/// A collection's state, for `get_collection` / `Advanced`.
#[derive(CandidType, Deserialize, Clone, Copy, Debug)]
pub enum CollectionStateView {
    Funding,
    Voting,
    DecidedSettle,
    DecidedRefund,
}

/// Outcome of an update — flat and typed.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum CollectionResult {
    // success
    Materialized,
    /// A `create` without a birth proof: derivation echo only, zero writes.
    Derived {
        collection: String,
        resolver: String,
    },
    Advanced(CollectionStateView),
    KeyBootstrapped,
    /// A verdict signature: `outcome` (settle=0/refund=1) + the schnorr signature.
    Signed {
        outcome: u8,
        signature: Vec<u8>,
    },
    // wiring / request
    Malformed,
    WrongTarget,
    NotBootstrapped,
    CollectionIdMismatch,
    BadBirthProof,
    FieldMismatch,
    CreatedAtOverflow,
    Underpaid,  // attached cycles below SIGN_PRICE
    NotDecided, // verdict not yet finalized
    SignFailed, // sign_with_schnorr rejected
    // registration validation
    DurationOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
    // state
    AlreadyExists,
    NotFound,
    NotRecipient,
    VoteCapReached,
    // step
    InvalidTransition,
    WeightBelowThreshold,
    DuplicateVoter,
    StepOverflow,
}

/// Configure from `init` overrides (testnet) or baked config. Mainnet traps on
/// any override — the pinned config + IC root key are authoritative.
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

/// Fetch and cache the threshold master public key (one-time, idempotent). Must
/// run after deploy before donors can query resolvers. `init` cannot (it is
/// sync) and timers are barred, so this is an explicit setup call.
#[ic_cdk::update]
async fn bootstrap() -> CollectionResult {
    if MASTER.with_borrow(|m| m.is_some()) {
        return CollectionResult::KeyBootstrapped;
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
        return CollectionResult::Malformed;
    };
    let (Ok(pk), Ok(cc)) = (
        <[u8; 32]>::try_from(res.public_key),
        <[u8; 32]>::try_from(res.chain_code),
    ) else {
        return CollectionResult::Malformed;
    };
    MASTER.with_borrow_mut(|m| *m = Some((pk, cc)));
    CollectionResult::KeyBootstrapped
}

// ---- Updates (fixed list; wallet-signed messages) ----

/// Lazy creation (recipient-signed). Admit the request (via `admit_create_collection`,
/// also run at the boundary so a bogus cert never reaches replicated execution),
/// then perform the one thing a boundary check must not: the write. A `create`
/// without a birth proof echoes the derivation (`Derived`, zero writes); a valid
/// birth proof materializes the `Funding` collection. `ready`/`recipient_cancel`
/// never materialize.
#[ic_cdk::update]
fn create_collection(text: String) -> CollectionResult {
    match admit_create_collection(&text) {
        // No proof: the whole method was a derivation echo — nothing to persist.
        Ok(Admitted::Echo {
            collection_id,
            resolver_key,
        }) => CollectionResult::Derived {
            collection: hex::encode(collection_id),
            resolver: bs58::encode(resolver_key).into_string(),
        },
        // Valid birth proof: the only step deferred past the boundary is the
        // replicated write (the boundary is read-only).
        Ok(Admitted::Materialize {
            collection_id,
            collection,
            recipient,
        }) => match state::materialize(collection_id, collection, recipient) {
            Ok(()) => CollectionResult::Materialized,
            Err(e) => state_error(e),
        },
        Err(e) => e,
    }
}

#[ic_cdk::update]
fn ready(text: String) -> CollectionResult {
    recipient_action(&text, "ready", conditional_funding_logic::Action::Ready)
}

#[ic_cdk::update]
fn recipient_cancel(text: String) -> CollectionResult {
    recipient_action(
        &text,
        "cancel",
        conditional_funding_logic::Action::RecipientCancel,
    )
}

/// A reputation-weighted vote. Admissibility (signature + weight proof ≥
/// `MIN_VOTE_WEIGHT`) is gated at the boundary via `admit_vote`; here the same
/// check runs authoritatively, then the `(collection_id, voter)` dedup + `V_MAX`
/// cap apply. Weight = the voter's reputation to the collection's recipient.
#[ic_cdk::update]
fn vote(text: String) -> CollectionResult {
    let (collection_id, v) = match admit_vote(&text) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match state::add_vote(&collection_id, v, now_secs(), V_MAX) {
        Ok(s) => CollectionResult::Advanced(state_view(s)),
        Err(e) => state_error(e),
    }
}

/// Largest ingress arg accepted. A legitimate signed request — even a birth
/// proof carrying a hex `cert` + `witness` — is a few KB; this leaves ample
/// headroom while dropping a multi-MB flood before it can force parsing, hex
/// decoding, or (on the vote path) BLS verification. Mirrors the relay's guard.
const MAX_ARG_BYTES: usize = 32 * 1024;

/// The boundary (non-negativity invariant #2, harness §6): a state-changing
/// ingress is admitted only if it would pass — its `admit_*` check (signature +
/// target + applicability proof) holds. Doomed/spam work never reaches the
/// replicated `update`, which re-checks authoritatively. Oversized args are
/// dropped first, for every method.
#[ic_cdk::inspect_message]
fn inspect_message() {
    if ic_cdk::api::msg_arg_data().len() > MAX_ARG_BYTES {
        return; // oversized ingress → dropped before execution, for free
    }
    let method = ic_cdk::api::msg_method_name();
    // `bootstrap` carries no `text` and is a one-shot fetch — admit only until
    // the master key lands, so a repeat is dropped for free.
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

/// Paid pull (fronted by the relay for `SIGN_PRICE`): the per-collection resolver
/// signs the finalized verdict — **one** signature reused by all `N` escrows
/// (they share `resolver = key([collection_id])`), which is the atomicity: a
/// single `outcome` settles or refunds the whole collection, no Merkle root/path.
/// Payment is accepted **before** `sign_with_schnorr`; a not-yet-`Decided`
/// collection is refused without charge.
#[ic_cdk::update]
async fn request_signature(chain: String, collection: String) -> CollectionResult {
    if ic_cdk::api::msg_cycles_available() < config::SIGN_PRICE {
        return CollectionResult::Underpaid;
    }
    if chain != config::CHAIN_ID {
        return CollectionResult::WrongTarget;
    }
    let Some(collection_id) = hex32(&collection) else {
        return CollectionResult::Malformed;
    };
    let outcome = match state::verdict(&collection_id, now_secs()) {
        Some(Outcome::Settle) => 0u8,
        Some(Outcome::Refund) => 1u8,
        None => return CollectionResult::NotDecided, // no charge until final
    };

    // Payment accepted only now, before the (paid) threshold signature.
    ic_cdk::api::msg_cycles_accept(config::SIGN_PRICE);
    let arg = SignWithSchnorrArgs {
        message: protocol::verdict_message(config::DOMAIN, &config::FACTORY, outcome),
        derivation_path: vec![collection_id.to_vec()],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: config::THRESHOLD_KEY.to_string(),
        },
        aux: None,
    };
    match sign_with_schnorr(&arg).await {
        Ok(res) => CollectionResult::Signed {
            outcome,
            signature: res.signature,
        },
        Err(_) => CollectionResult::SignFailed,
    }
}

// ---- Queries (free) ----

#[ic_cdk::query]
fn get_logic_version() -> u32 {
    LOGIC_VERSION
}

#[ic_cdk::query]
fn get_resolver(collection: String) -> Option<String> {
    let id = hex32(&collection)?;
    let (pk, cc) = MASTER.with_borrow(|m| *m)?;
    resolver::resolver(&pk, &cc, &id).map(|r| bs58::encode(r).into_string())
}

#[ic_cdk::query]
fn get_collection(collection: String) -> Option<CollectionStateView> {
    let id = hex32(&collection)?;
    state::collection_state(&id, now_secs()).map(state_view)
}

// ---- helpers ----

fn recipient_action(
    text: &str,
    action_name: &str,
    action: conditional_funding_logic::Action,
) -> CollectionResult {
    let (collection_id, signer) = match admit_action(text, action_name) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match state::recipient_action(&collection_id, &signer, action, now_secs()) {
        Ok(s) => CollectionResult::Advanced(state_view(s)),
        Err(e) => state_error(e),
    }
}

/// The voter's weight = their reputation to the collection's recipient, proven by
/// the book witness against the certified index root. `None` if the proof is
/// invalid or the collection is unknown.
fn voter_weight(
    req: &request::Request,
    collection_id: &[u8; 32],
    voter: &[u8; 32],
) -> Option<u128> {
    let recipient = state::collection_recipient(collection_id)?;
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
// Each state-changing method has an `admit_*` that proves it would pass — the
// cheap validity prefix plus, for a create/vote, the (expensive) birth/weight
// proof. The boundary (`inspect_message`) runs it to drop doomed/spam work
// before the replicated `update`; the `update` calls the same `admit_*` so the
// check is authoritative and never duplicated. Every `admit_*` is time-free, so
// it is safe to run in `inspect_message`; the `now`-dependent state ops
// (`add_vote`, `recipient_action`) stay in the update body.

/// A `create` that passed every proof/field check — what the update must still
/// commit. Split so the read-only boundary never writes: `Echo` is a pure
/// derivation (zero memory, harness #4), `Materialize` carries a validated birth
/// proof and the record to insert.
enum Admitted {
    /// No cert/witness → derivation echo only; the update writes nothing.
    Echo {
        collection_id: [u8; 32],
        resolver_key: [u8; 32],
    },
    /// A valid birth proof → the update materializes this `Funding` collection.
    Materialize {
        collection_id: [u8; 32],
        collection: Collection,
        recipient: [u8; 32],
    },
}

/// Admit a `create_collection`: signature + target + `collection_id` recompute/
/// match + resolver derivation, then — if a birth proof is attached — the blind
/// proof (BLS vs NNS root → witness → birth, field-matched) and the time-free
/// registration validation (`created_at` fixed from the birth slot, not `now`).
/// Everything the current update did **except** the final `state::materialize`,
/// which is the one write a read-only boundary must not perform. `Err` carries
/// the exact `CollectionResult` the update returns at that point — notably a
/// bogus `cert` (BLS fails) is `BadBirthProof`, the expensive flood the boundary
/// drops non-replicated.
fn admit_create_collection(text: &str) -> Result<Admitted, CollectionResult> {
    let Some((master_pk, chain_code)) = MASTER.with_borrow(|m| *m) else {
        return Err(CollectionResult::NotBootstrapped);
    };
    let Some(req) = request::parse(text) else {
        return Err(CollectionResult::Malformed);
    };
    if req.signed("action") != Some("create") || !target_ok(&req) {
        return Err(CollectionResult::WrongTarget);
    }
    let recipient = req.pubkey; // the recipient opens their own collection
    let (Some(collection_claimed), Some(duration), Some(recipient_nonce)) = (
        req.signed("collection").and_then(hex32),
        req.signed("duration").and_then(|s| parse_u64(Some(s))),
        parse_u64(req.extra("recipient_nonce")),
    ) else {
        return Err(CollectionResult::Malformed);
    };

    // Recompute the free `collection_id` from the presented fields + the config
    // snapshot; the signed `collection` pins it.
    let canister = ic_cdk::api::canister_self();
    let collection_id = protocol::collection_id(
        canister.as_slice(),
        recipient,
        recipient_nonce,
        duration,
        config::VOTING_PERIOD,
        config::APPROVAL_THRESHOLD,
        config::QUORUM_WEIGHT,
    );
    if collection_id != collection_claimed {
        return Err(CollectionResult::CollectionIdMismatch);
    }

    let Some(resolver_key) = resolver::resolver(&master_pk, &chain_code, &collection_id) else {
        return Err(CollectionResult::Malformed);
    };

    // No birth proof → derivation echo only (harness: create without a proof
    // grows no memory).
    let (Some(cert), Some(witness)) = (hex_vec(req.extra("cert")), hex_vec(req.extra("witness")))
    else {
        return Ok(Admitted::Echo {
            collection_id,
            resolver_key,
        });
    };

    // The first funded contribution's escrow fields (unsigned extras; pinned by
    // the birth proof at the derived address).
    let (Some(donor), Some(gross), Some(deadline), Some(nonce)) = (
        req.extra("donor").and_then(bs58_array::<32>),
        parse_u64(req.extra("gross")),
        parse_i64(req.extra("deadline")),
        parse_u64(req.extra("nonce")),
    ) else {
        return Err(CollectionResult::Malformed);
    };

    // Escrow address: fee_bps / fee_wallet come from config, not arguments
    // (spec §Членство). recipient / resolver come from the collection record.
    let Some(escrow) = address::escrow_address(
        config::FACTORY,
        donor,
        recipient,
        gross,
        deadline,
        resolver_key,
        config::FEE_BPS,
        config::FEE_WALLET,
        nonce,
    ) else {
        return Err(CollectionResult::BadBirthProof);
    };

    // Already materialized → a replayed birth proof is a no-op; drop it before the
    // BLS so a replay can't force the pairing on the replicated path (harness §6).
    // The update's `materialize` re-checks (`AlreadyExists`) authoritatively; an
    // echo (no proof) returned above is unaffected.
    if state::is_materialized(&collection_id) {
        return Err(CollectionResult::AlreadyExists);
    }

    // Blind birth proof: certificate (BLS vs NNS root) → root → witness → birth.
    let index = INDEX.with_borrow(|i| *i);
    let root_key = NNS_ROOT.with_borrow(|k| k.clone());
    let Some(combined_root) = birth::certified_root(&cert, &root_key, index.as_slice()) else {
        return Err(CollectionResult::BadBirthProof);
    };
    let Some(b) = birth::birth_from_witness(&witness, &combined_root, &escrow) else {
        return Err(CollectionResult::BadBirthProof);
    };
    // `gross` is committed via the escrow address, so the birth leaf no longer
    // carries it; only the leaf's `donor` is cross-checked here.
    if b.donor != donor {
        return Err(CollectionResult::FieldMismatch);
    }

    // created_at = the first contribution's birth slot → unix seconds. This is
    // what keeps the whole check time-free: the window anchors on the birth
    // slot, never on `now`.
    let Some(created_at) = config::slot_to_created_at(b.slot) else {
        return Err(CollectionResult::CreatedAtOverflow);
    };
    let inp = validate::RegInputs {
        duration,
        voting_period: config::VOTING_PERIOD,
        created_at,
        deadline,
    };
    if let Err(e) = validate::validate_registration(&inp) {
        return Err(reg_error(e));
    }

    let collection = Collection {
        state: State::Funding,
        votes: Vec::new(),
        created_at,
        duration,
        voting_period: config::VOTING_PERIOD,
        quorum_weight: config::QUORUM_WEIGHT,
        approval_threshold: config::APPROVAL_THRESHOLD,
    };
    Ok(Admitted::Materialize {
        collection_id,
        collection,
        recipient,
    })
}

/// Admit a recipient action (`ready`/`recipient_cancel`): signature + target +
/// the signer is the collection's recipient. Returns `(collection_id, signer)`;
/// the update's `state::recipient_action` stays authoritative on the transition.
/// Mirrors the state op's order exactly — `NotFound` when the collection is
/// absent, `NotRecipient` when the signer is not its recipient.
fn admit_action(text: &str, action_name: &str) -> Result<([u8; 32], [u8; 32]), CollectionResult> {
    let Some(req) = request::parse(text) else {
        return Err(CollectionResult::Malformed);
    };
    if req.signed("action") != Some(action_name) || !target_ok(&req) {
        return Err(CollectionResult::WrongTarget);
    }
    let Some(collection_id) = req.signed("collection").and_then(hex32) else {
        return Err(CollectionResult::Malformed);
    };
    match state::collection_recipient(&collection_id) {
        Some(r) if r == req.pubkey => Ok((collection_id, req.pubkey)),
        Some(_) => Err(CollectionResult::NotRecipient),
        None => Err(CollectionResult::NotFound),
    }
}

/// Admit a `vote`: signature + target + the weight proof meets `MIN_VOTE_WEIGHT`.
/// Returns `(collection_id, vote)`; `state::add_vote` applies the dedup + `V_MAX`
/// cap and the `Voting`-state gate.
fn admit_vote(text: &str) -> Result<([u8; 32], Vote), CollectionResult> {
    let Some(req) = request::parse(text) else {
        return Err(CollectionResult::Malformed);
    };
    if req.signed("action") != Some("vote") || !target_ok(&req) {
        return Err(CollectionResult::WrongTarget);
    }
    let Some(collection_id) = req.signed("collection").and_then(hex32) else {
        return Err(CollectionResult::Malformed);
    };
    let Some(done) = req.signed("choice").and_then(parse_choice) else {
        return Err(CollectionResult::Malformed);
    };
    // Cheap committed-state gate *before* the weight proof (harness §6): a doomed
    // vote (unknown / over cap / duplicate voter / not `Voting`) is dropped here —
    // at the boundary and without a BLS pairing — so a replay can't force the
    // pairing on the replicated path. `add_vote` re-checks authoritatively.
    if let Err(e) = state::vote_admits(&collection_id, &req.pubkey, V_MAX) {
        return Err(state_error(e));
    }
    let Some(weight) = voter_weight(&req, &collection_id, &req.pubkey) else {
        return Err(CollectionResult::BadBirthProof);
    };
    if weight < MIN_VOTE_WEIGHT {
        return Err(CollectionResult::WeightBelowThreshold);
    }
    Ok((
        collection_id,
        Vote {
            voter: req.pubkey,
            weight,
            done,
        },
    ))
}

/// The boundary dispatch: admit a state-changing ingress iff its `admit_*` check
/// passes. `is_ok()` collapses the typed verdict to accept/drop. A direct
/// `request_signature` ingress is relay-fronted, so it is dropped here (`_`).
fn admissible(method: &str, text: &str) -> bool {
    match method {
        "create_collection" => admit_create_collection(text).is_ok(),
        "ready" => admit_action(text, "ready").is_ok(),
        "recipient_cancel" => admit_action(text, "cancel").is_ok(),
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

/// The signed `canister`/`chain` fields must target this canister and cluster.
fn target_ok(req: &request::Request) -> bool {
    req.signed("canister") == Some(ic_cdk::api::canister_self().to_text().as_str())
        && req.signed("chain") == Some(config::CHAIN_ID)
}

/// Current time in unix seconds (the funding-window / escrow `deadline` unit).
fn now_secs() -> u64 {
    ic_cdk::api::time() / 1_000_000_000
}

fn state_view(s: State) -> CollectionStateView {
    match s {
        State::Funding => CollectionStateView::Funding,
        State::Voting { .. } => CollectionStateView::Voting,
        State::Decided {
            outcome: Outcome::Settle,
        } => CollectionStateView::DecidedSettle,
        State::Decided {
            outcome: Outcome::Refund,
        } => CollectionStateView::DecidedRefund,
    }
}

fn reg_error(e: validate::RegError) -> CollectionResult {
    use validate::RegError as E;
    match e {
        E::DurationOutOfRange => CollectionResult::DurationOutOfRange,
        E::DeadlineTooTight => CollectionResult::DeadlineTooTight,
        E::TimeOverflow => CollectionResult::TimeOverflow,
    }
}

fn state_error(e: state::StateError) -> CollectionResult {
    use conditional_funding_logic::StepError as Se;
    use state::StateError as E;
    match e {
        E::AlreadyExists => CollectionResult::AlreadyExists,
        E::NotFound => CollectionResult::NotFound,
        E::NotRecipient => CollectionResult::NotRecipient,
        E::VoteCapReached => CollectionResult::VoteCapReached,
        E::Step(Se::InvalidTransition) => CollectionResult::InvalidTransition,
        E::Step(Se::WeightBelowThreshold) => CollectionResult::WeightBelowThreshold,
        E::Step(Se::DuplicateVoter) => CollectionResult::DuplicateVoter,
        E::Step(Se::Overflow) => CollectionResult::StepOverflow,
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
