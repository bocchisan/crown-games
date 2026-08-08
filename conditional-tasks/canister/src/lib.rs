#![forbid(unsafe_code)]
// The same crate-level ban `crown-reduce`, the index and this game's `logic/`
// already carry, extended to the canister — the half that actually reads hostile
// bytes. Every state-changing method takes an attacker-chosen `text` and runs it
// twice: once non-replicated on the anonymous boundary and once replicated. A
// panic on either is a denial of service that costs the sender nothing, and an
// unmarked overflow is a wrong verdict. Tests are exempt — `unwrap` in a test *is*
// the assertion.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]
//! conditional-tasks canister — the reference class-B game. Blind (no chain
//! reads); `task_id` is a free `scope_id`, 1:1 to a single escrow (`B=1`).
//!
//! The update methods are thin wiring over the tested modules: parse a signed
//! request → derive/verify → apply to state. Nothing panics on the hot path
//! (`let else` throughout). Vote (`inspect_message` + weight proof) is T3;
//! `request_signature` (`sign_with_schnorr`) is T4. The full register→settle
//! flow is validated on the real network (T5).
//!
//! Index trust is split in two so the anonymous boundary stays cheap: the
//! certificate's BLS pairings run once on the paid `push_root`, and every
//! per-caller proof (birth, reputation) is a hash-tree walk against a cached
//! root. Verifying the certificate per call would exceed the 200M-instruction
//! `inspect_message` budget outright — a valid registration could not be
//! admitted at all.

use candid::{CandidType, Deserialize, Principal};
use conditional_tasks_logic::{Action, Outcome, State, Task, LOGIC_VERSION};
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
// derivation, escrow-address PDA) lives in one place — `crown-games-common` — so
// the BLS path is never copy-pasted per game. Re-exported to keep the public
// paths (`conditional_tasks::birth::…`) and the internal `birth::`/`address::`/
// `resolver::` call sites unchanged.
pub use crown_games_common::{
    address, birth, bs58_array, field, request, resolver, roots, signing, MAX_ARG_BYTES, V_MAX,
};

thread_local! {
    /// Cached threshold master (public key + chain code); resolvers derive from it.
    static MASTER: RefCell<Option<([u8; 32], [u8; 32])>> = const { RefCell::new(None) };
    /// Unix seconds of the last `bootstrap` attempt (0 = none). A timestamp, not
    /// a latch — see `bootstrap`.
    static LAST_BOOTSTRAP: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
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

// Every write this canister accepts is gated by a birth proof, so none of them
// needs a cap: an escrow is what pays for the byte it stores (`00 §11`). The one
// exception used to be `set_profile`, and the cap it needed (`P_MAX`) was itself
// the exposure — a table anyone could fill with fresh keys, after which no new
// recipient could ever be stored, on a canister whose state cannot be migrated.
// Both are gone with the table (`P7.14`, `state.rs`).

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

/// A produced verdict signature, for `get_signature`.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SignatureView {
    pub outcome: u8,
    pub signature: Vec<u8>,
}

/// Outcome of an update — flat and typed.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum TaskResult {
    // success
    Materialized,
    Advanced(TaskStateView),
    KeyBootstrapped,
    /// A verdict signature: `outcome` (settle=0/cancel=1) + the schnorr signature.
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
    TaskIdMismatch,
    BadBirthProof,
    FieldMismatch,
    Underpaid,  // attached cycles below SIGN_PRICE / ROOT_PRICE
    NotDecided, // verdict not yet finalized
    SignFailed, // sign_with_schnorr rejected
    /// A sibling call is already signing this scope — free, no charge. Retry and
    /// the produced signature is served from store.
    SignInFlight,
    // registration validation
    GrossBelowFloor,
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
            INDEX.with_borrow_mut(|i| *i = index);
            NNS_ROOT.with_borrow_mut(|k| *k = crown_games_common::IC_MAINNET_ROOT_KEY.to_vec());
        }
    }
}

/// Fetch and cache the threshold master public key (one-time, idempotent). Must
/// run after deploy before donors can query resolvers. `init` cannot (it is
/// sync) and timers are barred, so this is an explicit setup call.
/// **Rate-limited rather than latched, and the difference is the whole design.**
/// The key only lands *after* the `await`, so until it does, `MASTER` is still
/// empty and every concurrent caller passes the check below — anonymous, unpaid,
/// one management call each. The obvious fix is the claim-before-`await` that
/// `signing` uses; here it would be a bug. A claim taken before the `await`
/// survives a trapped callback, and this claim is not per-scope but per-canister:
/// one stuck flag and the game can never take its key, i.e. no resolver is ever
/// derivable and every escrow of every scope is left to `refund()`. So the gate is
/// a timestamp instead: it bounds the flood to one attempt per window and **heals
/// by itself**, because time passes whatever happened to the callback.
#[ic_cdk::update]
async fn bootstrap() -> TaskResult {
    if MASTER.with_borrow(|m| m.is_some()) {
        return TaskResult::KeyBootstrapped;
    }
    if !claim_bootstrap_window(bootstrap_now()) {
        return TaskResult::NotBootstrapped;
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
    };
    if let Err(e) = validate::validate_registration(config::MIN_GROSS, &inp) {
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
        // Admitted only while the key is missing **and** no recent attempt still
        // holds the window (`bootstrap`), so a burst is dropped free instead of
        // executing replicated. Read-only: the window is *taken* by the update,
        // never here — the boundary must not consume what it only inspects.
        //
        // Unlike the state checks in `admit_*`, this refusal is one time undoes
        // (the window reopens). That is fine for the method it guards and only
        // for it: `bootstrap` is an operator call with no deadline, retried
        // seconds later at no cost, and never on a user's critical path.
        let free = LAST_BOOTSTRAP.with(|t| bootstrap_window_free(t.get(), bootstrap_now()));
        if free && MASTER.with_borrow(|m| m.is_none()) {
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
fn push_root(cert: Vec<u8>) -> TaskResult {
    // `MAX_ARG_BYTES` lives in `inspect_message`, which **inter-canister calls do
    // not run** — and this method is only ever reached that way. Re-asserted here
    // for the same reason the relay re-asserts it on its own replicated path: the
    // cap is a cost knob (harness §6), and without it one caller can hand this
    // canister a multi-megabyte blob to CBOR-decode. Cheapest possible check, so
    // it goes ahead of the payment one.
    if cert.len() > MAX_ARG_BYTES {
        return TaskResult::Malformed;
    }
    if ic_cdk::api::msg_cycles_available() < config::ROOT_PRICE {
        return TaskResult::Underpaid;
    }
    ic_cdk::api::msg_cycles_accept(config::ROOT_PRICE);

    let index = INDEX.with_borrow(|i| *i);
    let root_key = NNS_ROOT.with_borrow(|k| k.clone());
    let Some(root) = birth::certified_root(&cert, &root_key, index.as_slice()) else {
        return TaskResult::BadBirthProof;
    };
    ROOTS.with_borrow_mut(|cache| roots::remember(cache, root));
    TaskResult::RootPushed
}

/// Paid pull (fronted by the relay for `SIGN_PRICE`): the per-scope resolver
/// signs the finalized verdict. One signature per scope, reused by its escrow's
/// `claim(outcome, sig)`.
///
/// Gate order mirrors the index's `ingest` (`crown-indexer/src/gate.rs`): the
/// cheapest, most decisive check wins first, and only the last step may charge.
/// A scope that was already signed is served **free** — the threshold signature
/// is deterministic in `(scope, outcome)` and the outcome is immutable once
/// `Decided` (harness §8), so re-signing would buy the same bytes twice. A
/// not-yet-`Decided` task is refused without charge; payment is accepted only
/// immediately before `sign_with_schnorr`, and on failure it is not refunded
/// (`01-standards §Тесты 4`).
#[ic_cdk::update]
async fn request_signature(chain: String, task: String) -> TaskResult {
    if chain != config::CHAIN_ID {
        return TaskResult::WrongTarget;
    }
    // Same reason as `push_root`: no `inspect_message` on the inter-canister path.
    // A `task` is 32 bytes in base58 and nothing else, so bound it before decoding.
    if task.len() > MAX_ARG_BYTES {
        return TaskResult::Malformed;
    }
    let Some(task_id) = bs58_array::<32>(&task) else {
        return TaskResult::Malformed;
    };
    // Already signed → the same bytes, for free. Ahead of the payment check on
    // purpose: a repeat costs one read, so it is never worth charging for.
    if let Some((outcome, signature)) = signing::cached(&task_id) {
        return TaskResult::Signed { outcome, signature };
    }
    if ic_cdk::api::msg_cycles_available() < config::SIGN_PRICE {
        return TaskResult::Underpaid;
    }
    let outcome = match state::verdict(&task_id, now_secs()) {
        Some(Outcome::Settle) => 0u8,
        Some(Outcome::Cancel) => 1u8,
        None => return TaskResult::NotDecided, // no charge until the verdict is final
    };
    // Claim the scope *before* the await: the store only lands after it, so
    // without this N concurrent requests would each miss the cache and each pay.
    // A losing sibling is free — it retries and finds the stored signature.
    if !signing::claim(task_id) {
        return TaskResult::SignInFlight;
    }

    // Payment accepted only now, before the (paid) threshold signature.
    ic_cdk::api::msg_cycles_accept(config::SIGN_PRICE);
    let arg = SignWithSchnorrArgs {
        // The consumer's own price list rides in the signed message, so the
        // signature cannot open an escrow that joined this scope by deriving the
        // resolver and set its own fee (`crown-games-common::wallet`, harness §9).
        message: protocol::verdict_message(
            config::DOMAIN,
            &config::FACTORY,
            outcome,
            config::FEE_BPS,
            &config::FEE_WALLET,
        ),
        derivation_path: vec![task_id.to_vec()],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: config::THRESHOLD_KEY.to_string(),
        },
        aux: None,
    };
    match sign_with_schnorr(&arg).await {
        Ok(res) => {
            signing::store(task_id, outcome, res.signature.clone());
            TaskResult::Signed {
                outcome,
                signature: res.signature,
            }
        }
        Err(_) => {
            signing::release(&task_id); // keep the scope retriable
            TaskResult::SignFailed
        }
    }
}

// ---- Queries (free) ----

#[ic_cdk::query]
fn get_logic_version() -> u32 {
    LOGIC_VERSION
}

#[ic_cdk::query]
fn get_resolver(task: String) -> Option<String> {
    let tid = bs58_array::<32>(&task)?;
    let (pk, cc) = MASTER.with_borrow(|m| *m)?;
    resolver::resolver(&pk, &cc, &tid).map(|r| bs58::encode(r).into_string())
}

#[ic_cdk::query]
fn get_task(task: String) -> Option<TaskStateView> {
    let tid = bs58_array::<32>(&task)?;
    state::task_state(&tid, now_secs()).map(state_view)
}

#[ic_cdk::query]
fn get_verdict(task: String) -> Option<TaskStateView> {
    let tid = bs58_array::<32>(&task)?;
    match state::verdict(&tid, now_secs())? {
        Outcome::Settle => Some(TaskStateView::DecidedSettle),
        Outcome::Cancel => Some(TaskStateView::DecidedCancel),
    }
}

/// The verdict signature already produced for a scope, if any. Free query — a
/// claimer that lost the race, or one that simply needs the bytes again, reads
/// them here instead of paying the relay to re-request a `SIGN_PRICE` pull.
#[ic_cdk::query]
fn get_signature(task: String) -> Option<SignatureView> {
    let tid = bs58_array::<32>(&task)?;
    let (outcome, signature) = signing::cached(&tid)?;
    Some(SignatureView { outcome, signature })
}

// ---- helpers ----

fn recipient_action(text: &str, action_name: &str, action: Action) -> TaskResult {
    let (task_id, signer) = match admit_action(text, action_name, &action) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match state::recipient_action(&task_id, &signer, action, now_secs()) {
        Ok(s) => TaskResult::Advanced(state_view(s)),
        Err(e) => state_error(e),
    }
}

/// The voter's weight = their reputation to the task's recipient, proven by the
/// book witness against an already-authenticated index root. `None` if the proof
/// is invalid or the task is unknown.
///
/// Like the birth proof, this is a pure hash-tree walk against the `ROOTS` cache
/// (`push_root` did the BLS, paid). The certificate must not be verified here:
/// `admit_vote` runs at the boundary, and two pairings per anonymous vote would
/// blow the 200M-instruction `inspect_message` budget — a *valid* vote could not
/// be admitted at all (spec §Методы, `cost.md §6` #2). No `cert` extra is read;
/// the root comes from the cache.
fn voter_weight(req: &request::Request, task_id: &[u8; 32], voter: &[u8; 32]) -> Option<u128> {
    let recipient = state::task_recipient(task_id)?;
    let weight_witness = field::hex_bytes(req.extra("weight_witness"))?;
    let chain = crown_games_common::chain_id(config::CHAIN_ID);
    ROOTS.with_borrow(|cache| roots::reputation(cache, &weight_witness, &chain, voter, &recipient))
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
    gross: u64,
    duration: i64,
    deadline: i64,
}

/// Admit a `register`: signature + target + fields + the blind birth proof (BLS
/// vs NNS root → witness → birth, field-matched). `Err` carries the exact
/// `TaskResult` the update returns.
fn admit_register(text: &str) -> Result<Registered, TaskResult> {
    let Some((master_pk, chain_code)) = MASTER.with_borrow(|m| *m) else {
        return Err(TaskResult::NotBootstrapped);
    };
    let Some(req) = request::parse(text, protocol::DOMAIN) else {
        return Err(TaskResult::Malformed);
    };
    if req.signed("action") != Some("register") || !target_ok(&req) {
        return Err(TaskResult::WrongTarget);
    }
    let donor = req.pubkey;
    let (Some(task_claimed), Some(text_hash), Some(duration)) = (
        req.signed("task").and_then(bs58_array::<32>),
        req.signed("text").and_then(field::hex32),
        field::i64_of(req.signed("duration")),
    ) else {
        return Err(TaskResult::Malformed);
    };
    let (Some(recipient), Some(gross), Some(deadline), Some(nonce), Some(witness)) = (
        req.extra("recipient").and_then(bs58_array::<32>),
        field::u64_of(req.extra("gross")),
        field::i64_of(req.extra("deadline")),
        field::u64_of(req.extra("nonce")),
        field::hex_bytes(req.extra("witness")),
    ) else {
        return Err(TaskResult::Malformed);
    };

    // The clock-free half of the registration policy, run here and not only in
    // the update (harness §6). Both refusals are permanent — `gross` and
    // `duration` are committed by `task_id` against an escrow that already exists
    // and cannot change — so no passage of time turns either into an acceptance,
    // which is exactly the condition for refusing at the boundary. Left to the
    // update they were a flood template: such a registration never materializes,
    // so `is_materialized` below never begins to refuse it, and the signed half of
    // a request carries no nonce — one doomed message replays forever and is
    // executed replicated every time. First, because it is the cheapest refusal
    // there is: ahead of the `task_id` hash, the resolver derivation and the
    // witness walk. `validate_registration` in the update stays authoritative.
    if let Err(e) = validate::validate_time_free(config::MIN_GROSS, gross, duration) {
        return Err(reg_error(e));
    }

    // Fee is the game's price list, not an argument (harness §9): `FEE_BPS` /
    // `FEE_WALLET` come from config. Taking them from the request would be a
    // circular check — the birth proof only attests that the escrow was created
    // with the *same* fee the caller presented, so a donor could bake `fee_wallet
    // = self` (or `fee_bps = 0`), pass every proof, and take the paid verdict
    // signature while the platform earned nothing. A mismatched escrow now fails
    // to derive to `task_claimed`/`address` at all.
    let canister = ic_cdk::api::canister_self();
    let task_id = protocol::task_id(
        canister.as_slice(),
        donor,
        recipient,
        gross,
        deadline,
        config::FEE_BPS,
        config::FEE_WALLET,
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
        config::FEE_BPS,
        config::FEE_WALLET,
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

    // Blind birth proof, boundary half: the witness is reconstructed against an
    // already-authenticated index root (`push_root` did the BLS, paid). A pure
    // hash-tree walk, O(log n) — it fits the `inspect_message` budget, which the
    // certificate's pairings do not (`push_root`).
    let Some(b) = ROOTS.with_borrow(|cache| roots::birth(cache, &witness, &address)) else {
        return Err(TaskResult::BadBirthProof);
    };
    // `gross` is committed via the escrow address (an input to `escrow_address`
    // above), so the birth leaf no longer carries it — the proof verifying at
    // `address` already binds `gross`. Only the leaf's `donor` is cross-checked.
    if b.donor != donor {
        return Err(TaskResult::FieldMismatch);
    }

    // One proof, not two. A second witness used to ride along here — the donor's
    // reputation, read only when the recipient's stored profile demanded it. The
    // profile is gone (`P7.14`), and with it the only registration-time reader of
    // the book: reputation is now proven on the vote path alone. The boundary got
    // cheaper by exactly one hash-tree walk.

    Ok(Registered {
        task_id,
        recipient,
        text_hash,
        gross,
        duration,
        deadline,
    })
}

/// Admit a recipient action (`accept`/`decline`/`ready`): signature + target +
/// the signer is the task's recipient + the stored state still admits the action.
/// Returns `(task_id, signer)`; the update's `state::recipient_action` stays
/// authoritative (it advances time first, so it may still refuse).
///
/// The state check is the point (harness §6, `cost.md §6` #2). Without it the
/// boundary passed every action from the right signer, and a doomed one — a
/// second `accept`, a `ready` on a decided task — was executed replicated and
/// billed to the canister. That is free for the sender and unbounded: the signed
/// half of a request is replayable (the extras carry no nonce), so one observed
/// valid message is a flood template.
fn admit_action(
    text: &str,
    action_name: &str,
    action: &Action,
) -> Result<([u8; 32], [u8; 32]), TaskResult> {
    let Some(req) = request::parse(text, protocol::DOMAIN) else {
        return Err(TaskResult::Malformed);
    };
    if req.signed("action") != Some(action_name) || !target_ok(&req) {
        return Err(TaskResult::WrongTarget);
    }
    let Some(task_id) = req.signed("task").and_then(bs58_array::<32>) else {
        return Err(TaskResult::Malformed);
    };
    match state::action_admits(&task_id, &req.pubkey, action) {
        Ok(()) => Ok((task_id, req.pubkey)),
        Err(e) => Err(state_error(e)),
    }
}

/// Admit a `vote`: signature + target + the weight proof meets `MIN_VOTE_WEIGHT`.
/// Returns `(task_id, vote)`; `state::add_vote` applies the dedup + `V_MAX` cap.
fn admit_vote(text: &str) -> Result<([u8; 32], conditional_tasks_logic::Vote), TaskResult> {
    let Some(req) = request::parse(text, protocol::DOMAIN) else {
        return Err(TaskResult::Malformed);
    };
    if req.signed("action") != Some("vote") || !target_ok(&req) {
        return Err(TaskResult::WrongTarget);
    }
    let Some(task_id) = req.signed("task").and_then(bs58_array::<32>) else {
        return Err(TaskResult::Malformed);
    };
    let Some(done) = req.signed("choice").and_then(field::choice) else {
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
        "accept" => admit_action(text, "accept", &Action::Accept).is_ok(),
        "decline" => admit_action(text, "decline", &Action::Decline).is_ok(),
        "ready" => admit_action(text, "ready", &Action::Ready).is_ok(),
        "vote" => admit_vote(text).is_ok(),
        _ => false,
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
        E::GrossBelowFloor => TaskResult::GrossBelowFloor,
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
        E::VoteCapReached => TaskResult::VoteCapReached,
        E::Step(Se::InvalidTransition) => TaskResult::InvalidTransition,
        E::Step(Se::WeightBelowThreshold) => TaskResult::WeightBelowThreshold,
        E::Step(Se::DuplicateVoter) => TaskResult::DuplicateVoter,
        E::Step(Se::Overflow) => TaskResult::StepOverflow,
    }
}

/// Seconds one `bootstrap` attempt reserves. Long enough that a burst collapses
/// to a single management call, short enough that an operator whose first attempt
/// failed (a key name the subnet does not provision) is not locked out.
const BOOTSTRAP_WINDOW_SECS: u64 = 30;

/// Unix seconds for the `bootstrap` window. Local rather than `now_secs`, whose
/// unit differs between games.
fn bootstrap_now() -> u64 {
    ic_cdk::api::time() / 1_000_000_000
}

/// Take the `bootstrap` window at `now`, or refuse because a recent attempt still
/// holds it. Taken only by the update; the boundary only reads it.
fn claim_bootstrap_window(now: u64) -> bool {
    LAST_BOOTSTRAP.with(|t| {
        if !bootstrap_window_free(t.get(), now) {
            return false;
        }
        t.set(now);
        true
    })
}

/// Whether the window is free — the pure half, shared by the boundary and the
/// update so the two cannot disagree.
///
/// `now < last` resolves to **open**, not shut. IC time is monotone per canister,
/// so it should not happen; the point is that if the assumption ever fails, this
/// gate degrades to "allow", the way every other branch here does. A gate that
/// answers "shut" to a clock it does not understand is the latch this deliberately
/// is not (see `bootstrap`).
fn bootstrap_window_free(last: u64, now: u64) -> bool {
    last == 0 || now < last || now.saturating_sub(last) >= BOOTSTRAP_WINDOW_SECS
}

ic_cdk::export_candid!();

#[cfg(test)]
mod bootstrap_window_tests {
    use super::*;

    /// The `bootstrap` window, tested on its pure half — the property that matters
    /// is that it **reopens**. A latch here would also pass "a burst is refused"
    /// and then brick the canister on a trapped callback (see `bootstrap`), so the
    /// reopening case is the one carrying the design, not the refusal.
    #[test]
    fn the_bootstrap_window_refuses_a_burst_and_reopens() {
        assert!(bootstrap_window_free(0, 0));
        assert!(bootstrap_window_free(0, 1_700_000_000));

        let t = 1_700_000_000;
        assert!(
            claim_bootstrap_window(t),
            "the first attempt takes the window"
        );
        assert!(
            !claim_bootstrap_window(t),
            "a sibling in the same round is refused"
        );
        assert!(
            !claim_bootstrap_window(t + BOOTSTRAP_WINDOW_SECS - 1),
            "still held one second before the window closes"
        );
        assert!(
            claim_bootstrap_window(t + BOOTSTRAP_WINDOW_SECS),
            "and it reopens on its own — nothing has to release it"
        );
        assert!(
            bootstrap_window_free(t + 100, t),
            "a backwards clock opens it"
        );
    }
}
