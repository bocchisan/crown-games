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
//! conditional-funding canister — a crowdfunding collection on the `two-outcome`
//! form. Blind and registryless: escrow membership is by the `resolver` field
//! (derivation), not a list. Area = collection, `B=N`; one verdict signature is
//! reused by all `N` escrows (F4).
//!
//! F2: lazy creation. `create_collection` takes a birth proof of the first funded
//! contribution and materializes the collection (fixing `created_at` from the
//! birth slot); the proof is required, and a `create` without one is dropped at
//! the boundary rather than answered with a derivation echo (see the method).
//! `ready`/`recipient_cancel` are free, self-signed, and never materialize.
//! Voting (F3) and the paid verdict pull (F4) land at their stages.

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
pub use crown_games_common::{
    address, birth, bs58_array, field, request, resolver, roots, signing, MAX_ARG_BYTES, V_MAX,
};

thread_local! {
    /// Cached threshold master (public key + chain code); resolvers derive from it.
    static MASTER: RefCell<Option<([u8; 32], [u8; 32])>> = const { RefCell::new(None) };
    /// crown-indexer principal (birth proofs are keyed to it).
    static INDEX: RefCell<Principal> = const { RefCell::new(Principal::anonymous()) };
    /// NNS root key that authenticates the index's certificate (blind proof).
    static NNS_ROOT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// Unix seconds of the last `bootstrap` attempt (0 = none). A timestamp, not
    /// a latch — see `bootstrap`.
    static LAST_BOOTSTRAP: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Recently verified index roots (newest last). A birth/reputation witness is
    /// admitted against any of them; the BLS that authenticates a root runs once,
    /// on the paid `push_root`, never on the anonymous boundary. Canister state,
    /// so it lives here; the cache policy is `roots` (one copy for every game).
    static ROOTS: RefCell<Vec<[u8; 32]>> = const { RefCell::new(Vec::new()) };
}

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

/// A produced verdict signature, for `get_signature`.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SignatureView {
    pub outcome: u8,
    pub signature: Vec<u8>,
}

/// A materialized collection, for `get_collection` — the state **and the window
/// it runs on**.
///
/// The anchors are not decoration: a contribution's escrow has to be born with
/// `deadline >= created_at + duration + voting_period + DEADLINE_MARGIN` (72h),
/// the canister verifies that only for the one contribution that materialized the
/// collection, and every later contribution joins by deriving the resolver
/// without ever being presented here. So the arithmetic is the donor's, and until
/// these fields were published there was nothing to do it with: `collection_id` is
/// a hash, so neither `created_at` nor the recipient is recoverable from it. A
/// client that guessed low made its escrow refundable before the verdict.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CollectionView {
    pub state: CollectionStateView,
    /// Birth time of the contribution the collection was materialized from (unix
    /// seconds, slot→time through the pinned anchor). Start of both windows.
    pub created_at: u64,
    /// Funding-window length; `Funding` runs `[created_at, created_at+duration]`.
    pub duration: u64,
    /// Voting-window length, from config and baked into `collection_id`.
    pub voting_period: u64,
    /// The collection's recipient (base58, as `get_resolver` returns the
    /// resolver) — a contribution's escrow salt commits it.
    pub recipient: String,
}

/// Outcome of an update — flat and typed.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum CollectionResult {
    // success
    Materialized,
    Advanced(CollectionStateView),
    KeyBootstrapped,
    /// A verdict signature: `outcome` (settle=0/refund=1) + the schnorr signature.
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
    CollectionIdMismatch,
    BadBirthProof,
    FieldMismatch,
    CreatedAtOverflow,
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
///
/// **Rate-limited rather than latched, and the difference is the whole design.**
/// The key only lands *after* the `await`, so until it does, `MASTER` is still
/// empty and every concurrent caller passes the check above — anonymous, unpaid,
/// one management call each. The obvious fix is the claim-before-`await` that
/// `signing` uses; here it would be a bug. A claim taken before the `await`
/// survives a trapped callback, and this claim is not per-scope but per-canister:
/// one stuck flag and the game can never take its key, i.e. no resolver is ever
/// derivable and every escrow of every collection is left to `refund()`. So the
/// gate is a timestamp instead: it bounds the flood to one attempt per window and
/// **heals by itself**, because time passes whatever happened to the callback.
#[ic_cdk::update]
async fn bootstrap() -> CollectionResult {
    if MASTER.with_borrow(|m| m.is_some()) {
        return CollectionResult::KeyBootstrapped;
    }
    if !claim_bootstrap_window(now_secs()) {
        return CollectionResult::NotBootstrapped;
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
/// then perform the one thing a boundary check must not: the write.
/// `ready`/`recipient_cancel` never materialize.
///
/// **A birth proof is required, and the derivation echo is gone** (`P8`). The
/// method used to answer a proof-less `create` with `Derived` — the `id` and the
/// resolver, zero writes — and the boundary admitted it, because "zero writes" was
/// read as "harmless". It is not: the sender signs their *own* `create` (the
/// recipient of a collection is `req.pubkey`), so anyone could mint a valid
/// proof-less request from a fresh key and have it executed **replicated** —
/// `verify_strict` + SHA-256 + an Ed25519 subkey derivation per copy, free to send,
/// unbounded, billed to this canister. That is exactly the flood template
/// `admit_action` was given a state check to stop (harness §6), and the echo was
/// the one path with no proof in front of it at all.
///
/// Nothing is lost with it. The caller already holds `collection_id` before the
/// call — it is a *signed* field of the message, so they computed it to sign — and
/// the resolver is `get_resolver`, a free `query`. The echo answered with what the
/// asker already had.
#[ic_cdk::update]
fn create_collection(text: String) -> CollectionResult {
    match admit_create_collection(&text) {
        // The only step deferred past the boundary is the replicated write (the
        // boundary is read-only).
        Ok(Admitted {
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
        let free = LAST_BOOTSTRAP.with(|t| bootstrap_window_free(t.get(), now_secs()));
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
fn push_root(cert: Vec<u8>) -> CollectionResult {
    // `MAX_ARG_BYTES` lives in `inspect_message`, which **inter-canister calls do
    // not run** — and this method is only ever reached that way. Re-asserted here
    // for the same reason the relay re-asserts it on its own replicated path: the
    // cap is a cost knob (harness §6), and without it one caller can hand this
    // canister a multi-megabyte blob to CBOR-decode. Cheapest possible check, so
    // it goes ahead of the payment one.
    if cert.len() > MAX_ARG_BYTES {
        return CollectionResult::Malformed;
    }
    if ic_cdk::api::msg_cycles_available() < config::ROOT_PRICE {
        return CollectionResult::Underpaid;
    }
    ic_cdk::api::msg_cycles_accept(config::ROOT_PRICE);

    let index = INDEX.with_borrow(|i| *i);
    let root_key = NNS_ROOT.with_borrow(|k| k.clone());
    let Some(root) = birth::certified_root(&cert, &root_key, index.as_slice()) else {
        return CollectionResult::BadBirthProof;
    };
    ROOTS.with_borrow_mut(|cache| roots::remember(cache, root));
    CollectionResult::RootPushed
}

/// Paid pull (fronted by the relay for `SIGN_PRICE`): the per-collection resolver
/// signs the finalized verdict — **one** signature reused by all `N` escrows
/// (they share `resolver = key([collection_id])`), which is the atomicity: a
/// single `outcome` settles or refunds the whole collection, no Merkle root/path.
/// Payment is accepted **before** `sign_with_schnorr`; a not-yet-`Decided`
/// collection is refused without charge.
#[ic_cdk::update]
async fn request_signature(chain: String, collection: String) -> CollectionResult {
    if chain != config::CHAIN_ID {
        return CollectionResult::WrongTarget;
    }
    // Same reason as `push_root`: no `inspect_message` on the inter-canister path.
    // A `collection` is 32 bytes of hex and nothing else, so bound it before
    // `hex32` decodes — a hex decode allocates half the input.
    if collection.len() > MAX_ARG_BYTES {
        return CollectionResult::Malformed;
    }
    let Some(collection_id) = field::hex32(&collection) else {
        return CollectionResult::Malformed;
    };
    // Already signed → the same bytes, for free. Ahead of the payment check on
    // purpose: a repeat costs one read, so it is never worth charging for. This
    // is also what makes "one signature reused by all N escrows" an amortization
    // in fact — the second escrow to claim pays nothing.
    if let Some((outcome, signature)) = signing::cached(&collection_id) {
        return CollectionResult::Signed { outcome, signature };
    }
    // The price the network charges today, not the one baked last build
    // (`sign_price`). Identical while the constant is the larger of the two,
    // which it is — this refuses only in the case where the old code would have
    // signed at a loss instead.
    let price = sign_price();
    if ic_cdk::api::msg_cycles_available() < price {
        return CollectionResult::Underpaid;
    }
    let outcome = match state::verdict(&collection_id, now_secs()) {
        Some(Outcome::Settle) => 0u8,
        Some(Outcome::Refund) => 1u8,
        None => return CollectionResult::NotDecided, // no charge until final
    };
    // Claim the scope *before* the await: the store only lands after it, so
    // without this N concurrent requests would each miss the store and each pay.
    if !signing::claim(collection_id) {
        return CollectionResult::SignInFlight;
    }

    // Payment accepted only now, before the (paid) threshold signature.
    ic_cdk::api::msg_cycles_accept(price);
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
        derivation_path: vec![collection_id.to_vec()],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: config::THRESHOLD_KEY.to_string(),
        },
        aux: None,
    };
    match sign_with_schnorr(&arg).await {
        Ok(res) => {
            signing::store(collection_id, outcome, res.signature.clone());
            CollectionResult::Signed {
                outcome,
                signature: res.signature,
            }
        }
        Err(_) => {
            signing::release(&collection_id); // keep the scope retriable
            CollectionResult::SignFailed
        }
    }
}

// ---- Queries (free) ----

#[ic_cdk::query]
fn get_logic_version() -> u32 {
    LOGIC_VERSION
}

#[ic_cdk::query]
fn get_resolver(collection: String) -> Option<String> {
    let id = field::hex32(&collection)?;
    let (pk, cc) = MASTER.with_borrow(|m| *m)?;
    resolver::resolver(&pk, &cc, &id).map(|r| bs58::encode(r).into_string())
}

/// The verdict signature already produced for a collection, if any. Free query —
/// every escrow after the first reads the bytes here instead of paying the relay
/// to re-request a `SIGN_PRICE` pull for a signature that already exists.
#[ic_cdk::query]
fn get_signature(collection: String) -> Option<SignatureView> {
    let id = field::hex32(&collection)?;
    let (outcome, signature) = signing::cached(&id)?;
    Some(SignatureView { outcome, signature })
}

#[ic_cdk::query]
fn get_collection(collection: String) -> Option<CollectionView> {
    let id = field::hex32(&collection)?;
    let v = state::collection_view(&id, now_secs())?;
    Some(CollectionView {
        state: state_view(v.state),
        created_at: v.created_at,
        duration: v.duration,
        voting_period: v.voting_period,
        recipient: bs58::encode(v.recipient).into_string(),
    })
}

// ---- helpers ----

fn recipient_action(
    text: &str,
    action_name: &str,
    action: conditional_funding_logic::Action,
) -> CollectionResult {
    let (collection_id, signer) = match admit_action(text, action_name, &action) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match state::recipient_action(&collection_id, &signer, action, now_secs()) {
        Ok(s) => CollectionResult::Advanced(state_view(s)),
        Err(e) => state_error(e),
    }
}

/// The voter's weight = their reputation to the collection's recipient, proven by
/// the book witness against an already-authenticated index root. `None` if the
/// proof is invalid or the collection is unknown.
///
/// Like the birth proof, this is a pure hash-tree walk against the `ROOTS` cache
/// (`push_root` did the BLS, paid). The certificate must not be verified here:
/// `admit_vote` runs at the boundary, and two pairings per anonymous vote would
/// blow the 200M-instruction `inspect_message` budget — a *valid* vote could not
/// be admitted at all (spec §Методы, `cost.md §6` #2).
fn voter_weight(
    req: &request::Request,
    collection_id: &[u8; 32],
    voter: &[u8; 32],
) -> Option<u128> {
    let recipient = state::collection_recipient(collection_id)?;
    let weight_witness = field::hex_bytes(req.extra("weight_witness"))?;
    let chain = crown_games_common::chain_id(config::CHAIN_ID);
    ROOTS.with_borrow(|cache| roots::reputation(cache, &weight_witness, &chain, voter, &recipient))
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
/// commit. A struct, not an enum: the only admissible `create` is one carrying a
/// validated birth proof, so there is exactly one thing left to do with it (the
/// write the read-only boundary must not perform).
struct Admitted {
    collection_id: [u8; 32],
    collection: Collection,
    recipient: [u8; 32],
}

/// Admit a `create_collection`: signature + target + `collection_id` recompute/
/// match + resolver derivation + the blind birth proof (witness against a cached
/// root, field-matched) + the time-free registration validation (`created_at`
/// fixed from the birth slot, not `now`). Everything the update does **except**
/// the final `state::materialize`, which is the one write a read-only boundary
/// must not perform. `Err` carries the exact `CollectionResult` the update
/// returns at that point — notably a witness against no cached root is
/// `BadBirthProof`, dropped non-replicated.
fn admit_create_collection(text: &str) -> Result<Admitted, CollectionResult> {
    let Some((master_pk, chain_code)) = MASTER.with_borrow(|m| *m) else {
        return Err(CollectionResult::NotBootstrapped);
    };
    let Some(req) = request::parse(text, protocol::DOMAIN) else {
        return Err(CollectionResult::Malformed);
    };
    if req.signed("action") != Some("create") || !target_ok(&req) {
        return Err(CollectionResult::WrongTarget);
    }
    let recipient = req.pubkey; // the recipient opens their own collection
    let (Some(collection_claimed), Some(duration), Some(recipient_nonce)) = (
        req.signed("collection").and_then(field::hex32),
        req.signed("duration").and_then(|s| field::u64_of(Some(s))),
        field::u64_of(req.extra("recipient_nonce")),
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

    // Already materialized → a replayed `create` is a no-op, and it is doomed on
    // `collection_id` alone. So it dies here, before the two derivations below —
    // a threshold subkey and a PDA bump search, both of which the boundary would
    // otherwise redo on every copy of a message that replays for free (the signed
    // half carries no nonce, harness §6). The update's `materialize` re-checks
    // (`AlreadyExists`) authoritatively.
    if state::is_materialized(&collection_id) {
        return Err(CollectionResult::AlreadyExists);
    }

    let Some(resolver_key) = resolver::resolver(&master_pk, &chain_code, &collection_id) else {
        return Err(CollectionResult::Malformed);
    };

    // The witness is mandatory: a `create` with nothing to prove has nothing to
    // execute replicated (see `create_collection`). Only the witness is needed —
    // the root it reconstructs against was authenticated earlier, on the paid
    // `push_root`.
    let Some(witness) = field::hex_bytes(req.extra("witness")) else {
        return Err(CollectionResult::Malformed);
    };

    // The first funded contribution's escrow fields (unsigned extras; pinned by
    // the birth proof at the derived address).
    let (Some(donor), Some(gross), Some(deadline), Some(nonce)) = (
        req.extra("donor").and_then(bs58_array::<32>),
        field::u64_of(req.extra("gross")),
        field::i64_of(req.extra("deadline")),
        field::u64_of(req.extra("nonce")),
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

    // Blind birth proof, boundary half: the witness is reconstructed against an
    // already-authenticated index root (`push_root` did the BLS, paid). A pure
    // hash-tree walk, O(log n) — it fits the `inspect_message` budget, which the
    // certificate's pairings do not (`push_root`).
    let Some(b) = ROOTS.with_borrow(|cache| roots::birth(cache, &witness, &escrow)) else {
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
        gross,
        duration,
        voting_period: config::VOTING_PERIOD,
        created_at,
        deadline,
    };
    if let Err(e) = validate::validate_registration(&inp, config::MIN_GROSS) {
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
    Ok(Admitted {
        collection_id,
        collection,
        recipient,
    })
}

/// Admit a recipient action (`ready`/`recipient_cancel`): signature + target +
/// the signer is the collection's recipient + the stored state still admits the
/// action. Returns `(collection_id, signer)`; the update's
/// `state::recipient_action` stays authoritative (it advances the clock first, so
/// it may still refuse). Mirrors the state op's order exactly — `NotFound` when
/// the collection is absent, `NotRecipient` when the signer is not its recipient.
///
/// The state check is the point (harness §6, `cost.md §6` #2): without it every
/// action from the right signer was admitted and the doomed ones were executed
/// replicated at the canister's expense — free for the sender, and unbounded,
/// since the signed half of a request carries no nonce and replays.
fn admit_action(
    text: &str,
    action_name: &str,
    action: &conditional_funding_logic::Action,
) -> Result<([u8; 32], [u8; 32]), CollectionResult> {
    let Some(req) = request::parse(text, protocol::DOMAIN) else {
        return Err(CollectionResult::Malformed);
    };
    if req.signed("action") != Some(action_name) || !target_ok(&req) {
        return Err(CollectionResult::WrongTarget);
    }
    let Some(collection_id) = req.signed("collection").and_then(field::hex32) else {
        return Err(CollectionResult::Malformed);
    };
    match state::action_admits(&collection_id, &req.pubkey, action) {
        Ok(()) => Ok((collection_id, req.pubkey)),
        Err(e) => Err(state_error(e)),
    }
}

/// Admit a `vote`: signature + target + the weight proof meets `MIN_VOTE_WEIGHT`.
/// Returns `(collection_id, vote)`; `state::add_vote` applies the dedup + `V_MAX`
/// cap and the `Voting`-state gate.
fn admit_vote(text: &str) -> Result<([u8; 32], Vote), CollectionResult> {
    let Some(req) = request::parse(text, protocol::DOMAIN) else {
        return Err(CollectionResult::Malformed);
    };
    if req.signed("action") != Some("vote") || !target_ok(&req) {
        return Err(CollectionResult::WrongTarget);
    }
    let Some(collection_id) = req.signed("collection").and_then(field::hex32) else {
        return Err(CollectionResult::Malformed);
    };
    let Some(done) = req.signed("choice").and_then(field::choice) else {
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
        "ready" => admit_action(text, "ready", &conditional_funding_logic::Action::Ready).is_ok(),
        "recipient_cancel" => admit_action(
            text,
            "cancel",
            &conditional_funding_logic::Action::RecipientCancel,
        )
        .is_ok(),
        "vote" => admit_vote(text).is_ok(),
        _ => false,
    }
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

/// Seconds one `bootstrap` attempt reserves. Long enough that a burst collapses
/// to a single management call, short enough that an operator whose first attempt
/// failed (a key name the subnet does not provision) is not locked out.
const BOOTSTRAP_WINDOW_SECS: u64 = 30;

/// Take the `bootstrap` window at `now`, or refuse because a recent attempt still
/// holds it. Read-only on the boundary (`peek` below) and taken only by the
/// update, so the boundary drops a burst for free without ever consuming the
/// window itself.
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
        E::GrossBelowFloor => CollectionResult::GrossBelowFloor,
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

/// What one verdict signature costs right now — the baked `SIGN_PRICE` or the
/// price the IC quotes for this key, whichever is larger. Policy and the reason
/// for it live in `crown_games_common::signing::sign_price`; the three lines of
/// CDK stay here, as with `now_secs`.
///
/// Exposed as a free `query` on purpose: it is the number the relay's own
/// `sign_price` has to stay at or above, and a value only readable by triggering
/// a refusal is a value nobody watches. Monitoring compares the two and sees the
/// day they cross **before** a settlement does.
fn sign_price() -> u128 {
    signing::sign_price(
        config::SIGN_PRICE,
        // 1 = `SchnorrAlgorithm::Ed25519 as u32`.
        ic_cdk::api::cost_sign_with_schnorr(config::THRESHOLD_KEY, 1).ok(),
    )
}

#[ic_cdk::query]
fn get_sign_price() -> u128 {
    sign_price()
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;

    /// The `bootstrap` window, tested on its pure half — the property that matters
    /// is that it **reopens**. A latch here would also pass "a burst is refused"
    /// and then brick the canister on a trapped callback (see `bootstrap`), so the
    /// reopening case is the one carrying the design, not the refusal.
    #[test]
    fn the_bootstrap_window_refuses_a_burst_and_reopens() {
        // Never attempted → open, whatever the clock says.
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

        // A replica clock that moves backwards must open the window, not wrap it
        // shut for 136 billion years.
        assert!(bootstrap_window_free(t + 100, t));
    }
}
