//! conditional-tasks canister — the reference class-B game. Blind (no chain
//! reads); `task_id` is a free `scope_id`, 1:1 to a single escrow (`B=1`).
//!
//! The update methods are thin wiring over the tested modules: parse a signed
//! request → derive/verify → apply to state. Nothing panics on the hot path
//! (`let else` throughout). Vote (`inspect_message` + weight proof) is T3;
//! `request_signature` (`sign_with_schnorr`) is T4. The full register→settle
//! flow is validated on the real network (T5).

use candid::{CandidType, Deserialize, Nat, Principal};
use conditional_tasks_logic::{Action, Outcome, State, Task, LOGIC_VERSION};
use ic_cdk_management_canister::{
    schnorr_public_key, sign_with_schnorr, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SignWithSchnorrArgs,
};
use std::cell::RefCell;

pub mod config;
pub mod protocol;
pub mod request;
pub mod state;
pub mod validate;

// The delicate, game-agnostic crypto (birth/reputation proof, threshold resolver
// derivation, escrow-address PDA) lives in one place — `crown-games-common` — so
// the BLS path is never copy-pasted per game. Re-exported to keep the public
// paths (`conditional_tasks::birth::…`) and the internal `birth::`/`address::`/
// `resolver::` call sites unchanged.
pub use crown_games_common::{address, birth, resolver};

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

/// Cap of votes per task (non-negativity invariant #7; cost.md §6 `V_MAX`).
const V_MAX: usize = 500;

/// Cap of distinct recipient profiles. `set_profile` is the only write not
/// gated by a birth proof — any freshly-signed key can add one — so without a
/// ceiling `PROFILES` grows for free and unbounded. Sized well above any real
/// recipient count; an existing recipient can always update in place, only a
/// new one past the cap is refused (non-negativity invariant #7, cost.md §6).
const P_MAX: usize = 100_000;

/// Deploy-time overrides (testnet): the index principal and the NNS root key
/// (PocketIC / a test IC differ from mainnet). Barred on mainnet.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    pub index: Principal,
    pub nns_root_key: Vec<u8>,
}

/// A task's state, for `get_task` / `Advanced`.
#[derive(CandidType, Deserialize, Clone, Copy, Debug)]
pub enum TaskStateView {
    Created,
    Accepted,
    Voting,
    DecidedSettle,
    DecidedCancel,
}

/// A recipient profile, for `get_profile`.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ProfileView {
    pub enabled: bool,
    pub min_gross: u64,
    pub min_reputation: Nat,
    pub counter: u64,
}

/// Outcome of an update — flat and typed.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum TaskResult {
    // success
    Materialized,
    Advanced(TaskStateView),
    ProfileSet,
    KeyBootstrapped,
    /// A verdict signature: `outcome` (settle=0/cancel=1) + the schnorr signature.
    Signed {
        outcome: u8,
        signature: Vec<u8>,
    },
    // wiring / request
    Malformed,
    WrongTarget,
    NotBootstrapped,
    TaskIdMismatch,
    BadBirthProof,
    FieldMismatch,
    ProfileMinBelowFloor,
    Underpaid,  // attached cycles below SIGN_PRICE
    NotDecided, // verdict not yet finalized
    SignFailed, // sign_with_schnorr rejected
    // registration validation
    ProfileDisabled,
    GrossBelowFloor,
    GrossBelowMinimum,
    ReputationBelowMinimum,
    DurationOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
    // state
    AlreadyExists,
    NotFound,
    NotRecipient,
    StaleCounter,
    VoteCapReached,
    ProfileCapReached,
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
                ic_cdk::trap(
                    "IC_MAINNET_ROOT_KEY is unset (P8: pin the NNS root key before mainnet)",
                );
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
async fn bootstrap() -> TaskResult {
    if MASTER.with_borrow(|m| m.is_some()) {
        return TaskResult::KeyBootstrapped;
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
        return TaskResult::Malformed;
    };
    let (Ok(pk), Ok(cc)) = (
        <[u8; 32]>::try_from(res.public_key),
        <[u8; 32]>::try_from(res.chain_code),
    ) else {
        return TaskResult::Malformed;
    };
    MASTER.with_borrow_mut(|m| *m = Some((pk, cc)));
    TaskResult::KeyBootstrapped
}

// ---- Updates (fixed list; wallet-signed messages) ----

/// Lazy creation: admit the birth proof (via `admit_register`, also run at the
/// boundary so a bogus proof never reaches here), validate registration against
/// the current time, and materialize the `Created` task. Without a valid birth
/// proof nothing is written.
#[ic_cdk::update]
fn register_task(text: String) -> TaskResult {
    let r = match admit_register(&text) {
        Ok(r) => r,
        Err(e) => return e,
    };
    // Time-dependent policy stays in the update (the boundary is time-free):
    // the deadline/duration bounds are checked against `now`.
    let inp = validate::RegInputs {
        gross: r.gross,
        duration: r.duration,
        deadline: r.deadline,
        voting_period: config::VOTING_PERIOD,
        now: now_secs(),
        donor_reputation: r.donor_reputation,
    };
    if let Err(e) = validate::validate_registration(&r.profile, config::MIN_GROSS, &inp) {
        return reg_error(e);
    }
    let task = Task {
        state: State::Created,
        votes: Vec::new(),
        deadline: r.deadline,
        voting_period: config::VOTING_PERIOD,
    };
    match state::materialize(r.task_id, task, r.recipient, r.text_hash) {
        Ok(()) => TaskResult::Materialized,
        Err(e) => state_error(e),
    }
}

#[ic_cdk::update]
fn accept(text: String) -> TaskResult {
    recipient_action(&text, "accept", Action::Accept)
}

#[ic_cdk::update]
fn decline(text: String) -> TaskResult {
    recipient_action(&text, "decline", Action::Decline)
}

#[ic_cdk::update]
fn ready(text: String) -> TaskResult {
    recipient_action(&text, "ready", Action::Ready)
}

#[ic_cdk::update]
fn set_profile(text: String) -> TaskResult {
    let (recipient, profile, counter) = match admit_profile(&text) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match state::set_profile(recipient, profile, counter, P_MAX) {
        Ok(()) => TaskResult::ProfileSet,
        Err(e) => state_error(e),
    }
}

/// A reputation-weighted vote. Admissibility (signature + weight proof ≥
/// `MIN_VOTE_WEIGHT`) is gated at the boundary via `admit_vote`; here the same
/// check runs authoritatively, then the `(task_id, voter)` dedup + `V_MAX` cap
/// apply. Weight = the voter's reputation to the task's recipient.
#[ic_cdk::update]
fn vote(text: String) -> TaskResult {
    let (task_id, v) = match admit_vote(&text) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match state::add_vote(&task_id, v, now_secs(), V_MAX) {
        Ok(s) => TaskResult::Advanced(state_view(s)),
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

/// Paid pull (fronted by the relay for `SIGN_PRICE`): the per-scope resolver
/// signs the finalized verdict. Payment is accepted **before** `sign_with_schnorr`;
/// a not-yet-`Decided` task is refused without charge. One signature per scope,
/// reused by its escrow's `claim(outcome, sig)`.
#[ic_cdk::update]
async fn request_signature(chain: String, task: String) -> TaskResult {
    if ic_cdk::api::msg_cycles_available() < config::SIGN_PRICE {
        return TaskResult::Underpaid;
    }
    if chain != config::CHAIN_ID {
        return TaskResult::WrongTarget;
    }
    let Some(task_id) = request::bs58_array::<32>(&task) else {
        return TaskResult::Malformed;
    };
    let outcome = match state::verdict(&task_id, now_secs()) {
        Some(Outcome::Settle) => 0u8,
        Some(Outcome::Cancel) => 1u8,
        None => return TaskResult::NotDecided, // no charge until the verdict is final
    };

    // Payment accepted only now, before the (paid) threshold signature.
    ic_cdk::api::msg_cycles_accept(config::SIGN_PRICE);
    let arg = SignWithSchnorrArgs {
        message: protocol::verdict_message(config::DOMAIN, &config::FACTORY, outcome),
        derivation_path: vec![task_id.to_vec()],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: config::THRESHOLD_KEY.to_string(),
        },
        aux: None,
    };
    match sign_with_schnorr(&arg).await {
        Ok(res) => TaskResult::Signed {
            outcome,
            signature: res.signature,
        },
        Err(_) => TaskResult::SignFailed,
    }
}

// ---- Queries (free) ----

#[ic_cdk::query]
fn get_logic_version() -> u32 {
    LOGIC_VERSION
}

#[ic_cdk::query]
fn get_resolver(task: String) -> Option<String> {
    let tid = request::bs58_array::<32>(&task)?;
    let (pk, cc) = MASTER.with_borrow(|m| *m)?;
    resolver::resolver(&pk, &cc, &tid).map(|r| bs58::encode(r).into_string())
}

#[ic_cdk::query]
fn get_task(task: String) -> Option<TaskStateView> {
    let tid = request::bs58_array::<32>(&task)?;
    state::task_state(&tid, now_secs()).map(state_view)
}

#[ic_cdk::query]
fn get_verdict(task: String) -> Option<TaskStateView> {
    let tid = request::bs58_array::<32>(&task)?;
    match state::verdict(&tid, now_secs())? {
        Outcome::Settle => Some(TaskStateView::DecidedSettle),
        Outcome::Cancel => Some(TaskStateView::DecidedCancel),
    }
}

#[ic_cdk::query]
fn get_profile(recipient: String) -> Option<ProfileView> {
    let r = request::bs58_array::<32>(&recipient)?;
    let (p, counter) = state::profile_and_counter(&r, config::MIN_GROSS);
    Some(ProfileView {
        enabled: p.enabled,
        min_gross: p.min_gross,
        min_reputation: Nat::from(p.min_reputation),
        counter,
    })
}

// ---- helpers ----

fn recipient_action(text: &str, action_name: &str, action: Action) -> TaskResult {
    let (task_id, signer) = match admit_action(text, action_name) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match state::recipient_action(&task_id, &signer, action, now_secs()) {
        Ok(s) => TaskResult::Advanced(state_view(s)),
        Err(e) => state_error(e),
    }
}

/// The voter's weight = their reputation to the task's recipient, proven by the
/// book witness against the certified index root. `None` if the proof is invalid
/// or the task is unknown.
fn voter_weight(req: &request::Request, task_id: &[u8; 32], voter: &[u8; 32]) -> Option<u128> {
    let recipient = state::task_recipient(task_id)?;
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
// cheap validity prefix plus, for a register/vote, the (expensive) proof. The
// boundary (`inspect_message`) runs it to drop doomed/spam work before the
// replicated `update`; the `update` calls the same `admit_*` so the check is
// authoritative and never duplicated. Every `admit_*` is time-free, so it is
// safe to run in `inspect_message`; the deadline/duration policy that needs
// `now` stays in `register_task`'s update body.

/// A registration that passed every proof/field check — the data the update
/// needs to validate against the current time and materialize.
struct Registered {
    task_id: [u8; 32],
    recipient: [u8; 32],
    text_hash: [u8; 32],
    profile: validate::Profile,
    gross: u64,
    duration: i64,
    deadline: i64,
    donor_reputation: Option<u128>,
}

/// Admit a `register`: signature + target + fields + the blind birth proof (BLS
/// vs NNS root → witness → birth, field-matched) + the reputation proof if the
/// profile demands one. `Err` carries the exact `TaskResult` the update returns.
fn admit_register(text: &str) -> Result<Registered, TaskResult> {
    let Some((master_pk, chain_code)) = MASTER.with_borrow(|m| *m) else {
        return Err(TaskResult::NotBootstrapped);
    };
    let Some(req) = request::parse(text) else {
        return Err(TaskResult::Malformed);
    };
    if req.signed("action") != Some("register") || !target_ok(&req) {
        return Err(TaskResult::WrongTarget);
    }
    let donor = req.pubkey;
    let (Some(task_claimed), Some(text_hash), Some(duration)) = (
        req.signed("task").and_then(request::bs58_array::<32>),
        hex32(req.signed("text")),
        parse_i64(req.signed("duration")),
    ) else {
        return Err(TaskResult::Malformed);
    };
    let (
        Some(recipient),
        Some(gross),
        Some(deadline),
        Some(fee_bps),
        Some(fee_wallet),
        Some(nonce),
        Some(cert),
        Some(witness),
    ) = (
        req.extra("recipient").and_then(request::bs58_array::<32>),
        parse_u64(req.extra("gross")),
        parse_i64(req.extra("deadline")),
        parse_u16(req.extra("fee_bps")),
        req.extra("fee_wallet").and_then(request::bs58_array::<32>),
        parse_u64(req.extra("nonce")),
        hex_vec(req.extra("cert")),
        hex_vec(req.extra("witness")),
    )
    else {
        return Err(TaskResult::Malformed);
    };

    let canister = ic_cdk::api::canister_self();
    let task_id = protocol::task_id(
        canister.as_slice(),
        donor,
        recipient,
        gross,
        deadline,
        fee_bps,
        fee_wallet,
        nonce,
        duration as u64,
        config::VOTING_PERIOD as u64,
    );
    if task_id != task_claimed {
        return Err(TaskResult::TaskIdMismatch);
    }

    let Some(resolver) = resolver::resolver(&master_pk, &chain_code, &task_id) else {
        return Err(TaskResult::Malformed);
    };
    let Some(address) = address::escrow_address(
        config::FACTORY,
        donor,
        recipient,
        gross,
        deadline,
        resolver,
        fee_bps,
        fee_wallet,
        nonce,
    ) else {
        return Err(TaskResult::BadBirthProof);
    };

    // Already materialized → a replayed birth proof is a no-op; drop it before the
    // BLS so a replay can't force the pairing on the replicated path (harness §6).
    // The update's `materialize` re-checks (`AlreadyExists`) authoritatively.
    if state::is_materialized(&task_id) {
        return Err(TaskResult::AlreadyExists);
    }

    // Blind birth proof: certificate (BLS vs NNS root) → root → witness → birth.
    let index = INDEX.with_borrow(|i| *i);
    let root_key = NNS_ROOT.with_borrow(|k| k.clone());
    let Some(combined_root) = birth::certified_root(&cert, &root_key, index.as_slice()) else {
        return Err(TaskResult::BadBirthProof);
    };
    let Some(b) = birth::birth_from_witness(&witness, &combined_root, &address) else {
        return Err(TaskResult::BadBirthProof);
    };
    // `gross` is committed via the escrow address (an input to `escrow_address`
    // above), so the birth leaf no longer carries it — the proof verifying at
    // `address` already binds `gross`. Only the leaf's `donor` is cross-checked.
    if b.donor != donor {
        return Err(TaskResult::FieldMismatch);
    }

    // Reputation proof only if the profile requires it (time-independent).
    let profile = state::profile(&recipient, config::MIN_GROSS);
    let donor_reputation = if profile.min_reputation > 0 {
        let Some(rep_witness) = hex_vec(req.extra("rep_witness")) else {
            return Err(TaskResult::ReputationBelowMinimum);
        };
        birth::reputation_from_witness(
            &rep_witness,
            &combined_root,
            &chain_id_hash(),
            &donor,
            &recipient,
        )
    } else {
        None
    };

    Ok(Registered {
        task_id,
        recipient,
        text_hash,
        profile,
        gross,
        duration,
        deadline,
        donor_reputation,
    })
}

/// Admit a recipient action (`accept`/`decline`/`ready`): signature + target +
/// the signer is the task's recipient. Returns `(task_id, signer)`; the update's
/// `state::recipient_action` is authoritative on the state transition.
fn admit_action(text: &str, action_name: &str) -> Result<([u8; 32], [u8; 32]), TaskResult> {
    let Some(req) = request::parse(text) else {
        return Err(TaskResult::Malformed);
    };
    if req.signed("action") != Some(action_name) || !target_ok(&req) {
        return Err(TaskResult::WrongTarget);
    }
    let Some(task_id) = req.signed("task").and_then(request::bs58_array::<32>) else {
        return Err(TaskResult::Malformed);
    };
    match state::task_recipient(&task_id) {
        Some(r) if r == req.pubkey => Ok((task_id, req.pubkey)),
        Some(_) => Err(TaskResult::NotRecipient),
        None => Err(TaskResult::NotFound),
    }
}

/// Admit a `set-profile`: signature + target + the recipient signs their own
/// profile + `min_gross ≥` the floor + the write would be admitted (monotonic
/// counter, table not full). Returns `(recipient, profile, counter)`.
fn admit_profile(text: &str) -> Result<([u8; 32], validate::Profile, u64), TaskResult> {
    let Some(req) = request::parse(text) else {
        return Err(TaskResult::Malformed);
    };
    if req.signed("action") != Some("set-profile") || !target_ok(&req) {
        return Err(TaskResult::WrongTarget);
    }
    let Some(recipient) = req.signed("recipient").and_then(request::bs58_array::<32>) else {
        return Err(TaskResult::Malformed);
    };
    if req.pubkey != recipient {
        return Err(TaskResult::NotRecipient); // the recipient signs their own profile
    }
    let (Some(min_gross), Some(min_reputation), Some(enabled), Some(counter)) = (
        parse_u64(req.signed("min_gross")),
        parse_u128(req.signed("min_reputation")),
        parse_bool(req.signed("enabled")),
        parse_u64(req.signed("counter")),
    ) else {
        return Err(TaskResult::Malformed);
    };
    if min_gross < config::MIN_GROSS {
        return Err(TaskResult::ProfileMinBelowFloor);
    }
    if let Err(e) = state::profile_admits(&recipient, counter, P_MAX) {
        return Err(state_error(e));
    }
    Ok((
        recipient,
        validate::Profile {
            enabled,
            min_gross,
            min_reputation,
        },
        counter,
    ))
}

/// Admit a `vote`: signature + target + the weight proof meets `MIN_VOTE_WEIGHT`.
/// Returns `(task_id, vote)`; `state::add_vote` applies the dedup + `V_MAX` cap.
fn admit_vote(text: &str) -> Result<([u8; 32], conditional_tasks_logic::Vote), TaskResult> {
    let Some(req) = request::parse(text) else {
        return Err(TaskResult::Malformed);
    };
    if req.signed("action") != Some("vote") || !target_ok(&req) {
        return Err(TaskResult::WrongTarget);
    }
    let Some(task_id) = req.signed("task").and_then(request::bs58_array::<32>) else {
        return Err(TaskResult::Malformed);
    };
    let Some(done) = req.signed("choice").and_then(parse_choice) else {
        return Err(TaskResult::Malformed);
    };
    // Cheap committed-state gate *before* the weight proof (harness §6): a doomed
    // vote (unknown / over cap / duplicate voter / not `Voting`) is dropped here —
    // at the boundary and without a BLS pairing — so a replay can't force the
    // pairing on the replicated path. `add_vote` re-checks authoritatively.
    if let Err(e) = state::vote_admits(&task_id, &req.pubkey, V_MAX) {
        return Err(state_error(e));
    }
    let Some(weight) = voter_weight(&req, &task_id, &req.pubkey) else {
        return Err(TaskResult::BadBirthProof);
    };
    if weight < conditional_tasks_logic::MIN_VOTE_WEIGHT {
        return Err(TaskResult::WeightBelowThreshold);
    }
    Ok((
        task_id,
        conditional_tasks_logic::Vote {
            voter: req.pubkey,
            weight,
            done,
        },
    ))
}

/// The boundary dispatch: admit a state-changing ingress iff its `admit_*` check
/// passes. `is_ok()` collapses the typed verdict to accept/drop.
fn admissible(method: &str, text: &str) -> bool {
    match method {
        "register_task" => admit_register(text).is_ok(),
        "accept" => admit_action(text, "accept").is_ok(),
        "decline" => admit_action(text, "decline").is_ok(),
        "ready" => admit_action(text, "ready").is_ok(),
        "set_profile" => admit_profile(text).is_ok(),
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

/// The signed `canister`/`chain` fields must target this canister and cluster.
fn target_ok(req: &request::Request) -> bool {
    req.signed("canister") == Some(ic_cdk::api::canister_self().to_text().as_str())
        && req.signed("chain") == Some(config::CHAIN_ID)
}

/// Current time in unix seconds (the escrow `deadline` unit).
fn now_secs() -> i64 {
    (ic_cdk::api::time() / 1_000_000_000) as i64
}

/// `ChainId` as the index keys the book: `sha256("crown-chain:v1:" ‖ id)`.
fn chain_id_hash() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"crown-chain:v1:");
    h.update(config::CHAIN_ID.as_bytes());
    h.finalize().into()
}

fn state_view(s: State) -> TaskStateView {
    match s {
        State::Created => TaskStateView::Created,
        State::Accepted => TaskStateView::Accepted,
        State::Voting { .. } => TaskStateView::Voting,
        State::Decided {
            outcome: Outcome::Settle,
        } => TaskStateView::DecidedSettle,
        State::Decided {
            outcome: Outcome::Cancel,
        } => TaskStateView::DecidedCancel,
    }
}

fn reg_error(e: validate::RegError) -> TaskResult {
    use validate::RegError as E;
    match e {
        E::ProfileDisabled => TaskResult::ProfileDisabled,
        E::GrossBelowFloor => TaskResult::GrossBelowFloor,
        E::GrossBelowMinimum => TaskResult::GrossBelowMinimum,
        E::ReputationBelowMinimum => TaskResult::ReputationBelowMinimum,
        E::DurationOutOfRange => TaskResult::DurationOutOfRange,
        E::DeadlineTooTight => TaskResult::DeadlineTooTight,
        E::TimeOverflow => TaskResult::TimeOverflow,
    }
}

fn state_error(e: state::StateError) -> TaskResult {
    use conditional_tasks_logic::StepError as Se;
    use state::StateError as E;
    match e {
        E::AlreadyExists => TaskResult::AlreadyExists,
        E::NotFound => TaskResult::NotFound,
        E::NotRecipient => TaskResult::NotRecipient,
        E::StaleCounter => TaskResult::StaleCounter,
        E::VoteCapReached => TaskResult::VoteCapReached,
        E::ProfileCapReached => TaskResult::ProfileCapReached,
        E::Step(Se::InvalidTransition) => TaskResult::InvalidTransition,
        E::Step(Se::WeightBelowThreshold) => TaskResult::WeightBelowThreshold,
        E::Step(Se::DuplicateVoter) => TaskResult::DuplicateVoter,
        E::Step(Se::Overflow) => TaskResult::StepOverflow,
    }
}

fn parse_u64(s: Option<&str>) -> Option<u64> {
    s?.parse().ok()
}
fn parse_i64(s: Option<&str>) -> Option<i64> {
    s?.parse().ok()
}
fn parse_u16(s: Option<&str>) -> Option<u16> {
    s?.parse().ok()
}
fn parse_u128(s: Option<&str>) -> Option<u128> {
    s?.parse().ok()
}
fn parse_bool(s: Option<&str>) -> Option<bool> {
    match s? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}
fn hex32(s: Option<&str>) -> Option<[u8; 32]> {
    hex::decode(s?).ok()?.try_into().ok()
}
fn hex_vec(s: Option<&str>) -> Option<Vec<u8>> {
    hex::decode(s?).ok()
}

ic_cdk::export_candid!();
