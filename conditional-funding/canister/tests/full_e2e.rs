//! Full canister-game e2e (PocketIC): the birth-proof / signing path that needs a
//! real index + threshold key, without a live Solana RPC outcall. Mirrors the
//! reference game's `conditional-tasks/canister/tests/full_e2e.rs`.
//!
//! A mock SOL RPC canister at the index's pinned `SOL_RPC` principal returns a
//! synthetic `create_escrow` transaction, so a paid `ingest` (fronted by the relay
//! proxy with cycles) folds it into a **birth**. That birth is then consumed by
//! `create_collection` (a real recipient-signed request + witness against a
//! `push_root`-cached index root) → materialize; then `recipient_cancel` →
//! `request_signature` produces a real threshold `Signed{Refund}` verdict for the
//! collection's resolver — the one signature all `N` escrows reuse.
//!
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic cargo test --test full_e2e

use candid::{CandidType, Decode, Deserialize, Encode, Principal, Reserved};
use conditional_funding::{protocol, CollectionResult, CollectionStateView, InitArgs};
use ed25519_dalek::{Signer, SigningKey};
use pocket_ic::{PocketIc, PocketIcBuilder, Time};
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    transaction::Transaction,
};

const GAME_WASM: &str = "../target/e2e/wasm32-unknown-unknown/release/conditional_funding.wasm";
// `config/testnet.toml` — baked into `collection_id`, so the test must use the
// same values the canister does or the id it recomputes will not match.
const VOTING_PERIOD: u64 = 120;
const APPROVAL_THRESHOLD: u16 = 5_000;
const QUORUM_WEIGHT: u128 = 150_000;
// The fee is the game's price list, not a request field (harness §9): the escrow
// must be born with exactly these or it derives to a different address.
const FEE_BPS: u16 = 300;
const FEE_WALLET_B58: &str = "FS6ZNuPxXqWSGzwXEQpfoxikDksbEzmrXGZDFXmFj6vS";
const SIGN_PRICE: u128 = 26_200_000_000;
const ROOT_PRICE: u128 = 1_000_000_000;
const SEP: &str = "\n---\n";
// The devnet slot→time anchor and slope, same file. `created_at` comes from the
// birth slot through them, so the test has to invert the *pinned* anchor to land
// a birth inside the funding window — a slot picked against a zero anchor now
// maps decades away and the first lazy tick refunds the collection.
const SLOT_MS: u64 = 400;
const GENESIS_SLOT: u64 = 479_731_554;
const GENESIS_UNIX: u64 = 1_785_326_212;

/// Build the conditional-funding wasm into an isolated target dir — not to select
/// a profile (there is one devnet profile, `testnet`, and it names the key the
/// replica actually provisions), but so this nested `cargo build` never contends
/// with the outer `cargo test` for the workspace build lock.
///
/// Always invoked, never skipped on "the file is already there": these bytes
/// depend on `config/testnet.toml`, and an artifact cached from an earlier
/// config silently disagrees with the ids this test derives. A stale `fee_wallet`
/// alone moves every escrow address, so the birth proof lands nowhere and the
/// boundary drops a perfectly valid `create_collection` with nothing to read but
/// "rejected". Cargo no-ops when nothing changed, so the guard cost nothing and
/// bought a whole class of unexplainable failures.
fn game_wasm() -> Vec<u8> {
    {
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "-p",
                "conditional-funding",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "--target-dir",
                "../target/e2e",
            ])
            .status()
            .expect("build conditional-funding wasm");
        assert!(status.success());
    }
    std::fs::read(GAME_WASM).expect("read conditional-funding wasm")
}

/// Non-negativity, **measured rather than promised** (`cost.md §6`,
/// `01-standards §Тесты 4,12`). A paid pull must leave the canister no poorer than
/// it found it: it takes `price` in and spends execution (plus, for the signature,
/// the threshold fee the management canister charges *us*). So the balance delta
/// across the call has to be ≥ 0, and how much of `price` survived is the margin.
///
/// Until this existed, "`SIGN_PRICE` ≥ measured `sign_with_schnorr`" and
/// "`ROOT_PRICE` ≥ two BLS pairings" were sentences in `cost.md` with nothing
/// executing them: both prices are baked constants and a config edit that dropped
/// either below cost would have gone green all the way to mainnet, where the
/// symptom is a slow cycle leak, not a failure.
///
/// **What it is not:** a mainnet number. PocketIC runs a 13-node application
/// subnet; the games live on a 34-node fiduciary one, where both execution and the
/// threshold signature cost roughly 2.6× more. So this is a floor — it catches a
/// price set below even the cheap subnet's cost, and a dependency bump that makes
/// the pairings dramatically more expensive. The mainnet figure stays a cost-gate
/// measurement (`07-build-plan §P8`), and the margin printed below is what that
/// gate should be comparing against.
fn assert_price_covers_the_work(what: &str, before: u128, after: u128, price: u128) {
    let spent = price.saturating_sub(after.saturating_sub(before));
    println!(
        "[cost] {what}: charged {price}, spent {spent}, margin {} cycles",
        price.saturating_sub(spent)
    );
    assert!(
        after >= before,
        "{what} charged {price} cycles and left the canister {} poorer — the price \
         no longer covers the work it triggers (spent ~{spent})",
        before.saturating_sub(after)
    );
}

/// `<message>\n---\npubkey: ..\nsignature: ..\n<extras>` (the shared wire format).
fn signed_request(sk: &SigningKey, message: &str, extras: &[(&str, String)]) -> String {
    let pk = bs58::encode(sk.verifying_key().to_bytes()).into_string();
    let sig = bs58::encode(sk.sign(message.as_bytes()).to_bytes()).into_string();
    let mut out = format!("{message}{SEP}pubkey: {pk}\nsignature: {sig}");
    for (k, v) in extras {
        out.push_str(&format!("\n{k}: {v}"));
    }
    out
}

// crown-indexer `config/testnet.toml`. Must track it: the index accepts nothing
// below its own INGEST_PRICE, so a stale value here reads as `Underpaid` and the
// ingest silently folds nothing.
const INGEST_PRICE: u128 = 17_000_000_000;
const SOL_RPC: [u8; 10] = [0, 0, 0, 0, 2, 48, 4, 68, 1, 1]; // tghme-zyaaa-aaaar-qarca-cai
const TWO_OUTCOME_FACTORY: &str = "BGVQrwSwkFQspL69DjGBFgKSgL6rutPqgcgEskmi8A4y"; // pinned in the index

const INDEX_WASM: &str =
    "../../../crown-indexer/target/wasm32-unknown-unknown/release/crown_indexer.wasm";
const MOCK_DIR: &str = "../../e2e-fixtures/mock-sol-rpc";
const MOCK_WASM: &str =
    "../../e2e-fixtures/mock-sol-rpc/target/wasm32-unknown-unknown/release/mock_sol_rpc.wasm";
const PROXY_DIR: &str = "../../e2e-fixtures/relay-proxy";
const PROXY_WASM: &str =
    "../../e2e-fixtures/relay-proxy/target/wasm32-unknown-unknown/release/relay_proxy.wasm";

// Local mirrors of the index's `.did` result types.
#[derive(CandidType, Deserialize, Debug)]
enum IngestResult {
    LowBalance,
    Applied {
        settlements: u64,
        anomalies: u64,
        births: u64,
    },
    Underpaid,
    Duplicate,
    NotFound,
}
#[derive(CandidType, Deserialize, Debug)]
struct BirthView {
    slot: u64,
    donor: Vec<u8>,
}

// SOL RPC `getTransaction` reply — a structural copy of `crown_indexer::parse`'s
// candid types. Copied rather than imported so the test binary does not link the
// index canister (duplicate `canister_init` symbols).
#[derive(CandidType, Deserialize, Clone)]
enum MultiGetTransactionResult {
    Consistent(GetTransactionResult),
    Inconsistent(Vec<(Reserved, GetTransactionResult)>),
}
#[derive(CandidType, Deserialize, Clone)]
enum GetTransactionResult {
    Ok(Option<TransactionReply>),
    Err(Reserved),
}
#[derive(CandidType, Deserialize, Clone)]
struct TransactionReply {
    slot: u64,
    transaction: EncodedTxWithMeta,
}
#[derive(CandidType, Deserialize, Clone)]
struct EncodedTxWithMeta {
    meta: Option<TxMeta>,
    transaction: EncodedTransaction,
}
#[derive(CandidType, Deserialize, Clone)]
#[allow(non_camel_case_types)]
enum EncodedTransaction {
    binary(String, Encoding),
    legacyBinary(String),
}
#[derive(CandidType, Deserialize, Clone)]
#[allow(non_camel_case_types)]
enum Encoding {
    base58,
    base64,
}
#[derive(CandidType, Deserialize, Clone)]
#[allow(non_snake_case)]
struct TxMeta {
    status: TxStatus,
    innerInstructions: Option<Vec<InnerInstructions>>,
    loadedAddresses: Option<LoadedAddresses>,
}
#[derive(CandidType, Deserialize, Clone)]
enum TxStatus {
    Ok,
    Err(Reserved),
}
#[derive(CandidType, Deserialize, Clone)]
struct InnerInstructions {
    instructions: Vec<Ix>,
    index: u8,
}
#[derive(CandidType, Deserialize, Clone)]
#[allow(non_camel_case_types)]
enum Ix {
    compiled(CompiledInstruction),
}
#[derive(CandidType, Deserialize, Clone)]
#[allow(non_snake_case)]
struct CompiledInstruction {
    data: String,
    accounts: Vec<u8>,
    programIdIndex: u8,
    stackHeight: Option<u32>,
}
#[derive(CandidType, Deserialize, Clone)]
struct LoadedAddresses {
    writable: Vec<String>,
    readonly: Vec<String>,
}

fn build(dir: &str, extra: &[&str]) {
    let mut args = vec!["build", "--release", "--target", "wasm32-unknown-unknown"];
    args.extend_from_slice(extra);
    let status = std::process::Command::new("cargo")
        .args(&args)
        .current_dir(dir)
        .status()
        .expect("cargo build");
    assert!(status.success(), "build failed in {dir}");
}

fn wasm(path: &str, dir: &str, extra: &[&str]) -> Vec<u8> {
    if !std::path::Path::new(path).exists() {
        build(dir, extra);
    }
    std::fs::read(path).unwrap_or_else(|_| panic!("read wasm {path}"))
}

fn anon() -> Principal {
    Principal::anonymous()
}

fn factory() -> [u8; 32] {
    b58_32(TWO_OUTCOME_FACTORY)
}

fn fee_wallet() -> [u8; 32] {
    b58_32(FEE_WALLET_B58)
}

fn b58_32(s: &str) -> [u8; 32] {
    bs58::decode(s).into_vec().unwrap().try_into().unwrap()
}

/// Anchor discriminator: `sha256("global:create_escrow")[0..8]`.
fn create_escrow_disc() -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"global:create_escrow");
    let d = h.finalize();
    let mut o = [0u8; 8];
    o.copy_from_slice(&d[0..8]);
    o
}

/// A synthetic `create_escrow` transaction for `(donor, escrow)` that the index
/// recognizes as a birth (`escrow == PDA(factory, [b"escrow", salt])`).
fn birth_tx(donor: Pubkey, escrow: Pubkey, salt: [u8; 32]) -> String {
    let mut data = create_escrow_disc().to_vec();
    data.extend_from_slice(&salt); // salt @ 8..40 — all `decode_birth` needs past the disc
    let ix = Instruction {
        program_id: Pubkey::new_from_array(factory()),
        accounts: vec![
            AccountMeta::new(donor, false),  // account 0 = donor
            AccountMeta::new(escrow, false), // account 1 = escrow
        ],
        data,
    };
    let msg = Message::new(&[ix], Some(&donor));
    let tx = Transaction::new_unsigned(msg);
    bs58::encode(bincode::serialize(&tx).unwrap()).into_string()
}

// ---- Reputation: what a vote actually weighs ----
//
// A vote weighs the voter's book reputation to the collection's recipient, and the
// only way into the book is an honest settlement read from chain (`00 §9`). The
// index recognizes one when a `Settled` event-CPI of the **pinned splitter** is
// cross-checked by a real `TransferChecked` in the same transaction — same mint,
// amount and authority (`crown-indexer/src/recognize.rs`). The recognition roots
// below are copies of the index's devnet profile, for the same reason
// `TWO_OUTCOME_FACTORY` is: the test must not link the index canister.

/// `splitter` of `crown-indexer/config/testnet.toml`.
const SPLITTER: &str = "DKs2C9dRJSnZsERdD58cUVXMracvVTDS19PWvUz98GrN";
/// `usdc` of the same profile — the mint the cross-check demands.
const USDC: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
/// SPL Token program id (`Tokenkeg…`) — a Solana constant, not a config value.
const TOKEN_PROGRAM: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];
/// SPL Token `TransferChecked` tag (data byte 0).
const TRANSFER_CHECKED_TAG: u8 = 12;
/// Anchor's `emit_cpi!` self-CPI tag: the first 8 bytes of an event-CPI's data.
const EVENT_IX_TAG: [u8; 8] = [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d];

/// Anchor discriminator `sha256("event:Settled")[0..8]`.
fn settled_disc() -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"event:Settled");
    let d = h.finalize();
    let mut o = [0u8; 8];
    o.copy_from_slice(&d[0..8]);
    o
}

/// A direct donation as the chain shows it: the splitter's `Settled` event-CPI
/// plus the `TransferChecked` that backs it. The index folds it into `gross` of
/// reputation for `donor` at `recipient` — which is the weight a vote carries.
fn settlement_tx(donor: Pubkey, recipient: [u8; 32], gross: u64) -> String {
    let mut transfer = vec![TRANSFER_CHECKED_TAG];
    transfer.extend_from_slice(&gross.to_le_bytes());
    transfer.push(6); // decimals (USDC)
    let transfer_ix = Instruction {
        program_id: Pubkey::new_from_array(TOKEN_PROGRAM),
        // `[source, mint, destination, authority]`; the cross-check reads 1 and 3.
        accounts: vec![
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(b58_32(USDC)), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(donor, true),
        ],
        data: transfer,
    };
    let mut event = EVENT_IX_TAG.to_vec();
    event.extend_from_slice(&settled_disc());
    event.extend_from_slice(&donor.to_bytes());
    event.extend_from_slice(&recipient);
    event.extend_from_slice(&gross.to_le_bytes());
    let settled_ix = Instruction {
        program_id: Pubkey::new_from_array(b58_32(SPLITTER)),
        accounts: vec![],
        data: event,
    };
    let msg = Message::new(&[transfer_ix, settled_ix], Some(&donor));
    let tx = Transaction::new_unsigned(msg);
    bs58::encode(bincode::serialize(&tx).unwrap()).into_string()
}

fn consistent_reply(tx_b58: String, slot: u64) -> MultiGetTransactionResult {
    MultiGetTransactionResult::Consistent(GetTransactionResult::Ok(Some(TransactionReply {
        slot,
        transaction: EncodedTxWithMeta {
            meta: Some(TxMeta {
                status: TxStatus::Ok,
                innerInstructions: None,
                loadedAddresses: None,
            }),
            transaction: EncodedTransaction::binary(tx_b58, Encoding::base58),
        },
    })))
}

/// Install the index, the mock SOL RPC (at the pinned `SOL_RPC` id), and the relay
/// proxy. Returns `(pic, index, mock, proxy)`.
fn setup() -> (PocketIc, Principal, Principal, Principal) {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_fiduciary_subnet()
        .with_application_subnet()
        .build();
    let app = pic.topology().get_app_subnets()[0];

    let index = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(index, 5_000_000_000_000);
    pic.install_canister(
        index,
        wasm(INDEX_WASM, "../../../crown-indexer", &["--lib"]),
        Encode!().unwrap(),
        None,
    );

    let sol_rpc = Principal::from_slice(&SOL_RPC);
    let mock = pic
        .create_canister_with_id(None, None, sol_rpc)
        .expect("create mock at the SOL_RPC principal");
    pic.add_cycles(mock, 5_000_000_000_000);
    pic.install_canister(
        mock,
        wasm(MOCK_WASM, MOCK_DIR, &[]),
        Encode!().unwrap(),
        None,
    );

    let proxy = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(proxy, 100_000_000_000_000);
    pic.install_canister(
        proxy,
        wasm(PROXY_WASM, PROXY_DIR, &[]),
        Encode!().unwrap(),
        None,
    );

    (pic, index, mock, proxy)
}

/// Relay `method` to `target` with `cycles` attached, returning the raw reply.
fn relay(
    pic: &PocketIc,
    proxy: Principal,
    target: Principal,
    method: &str,
    inner: Vec<u8>,
    cycles: u128,
) -> Vec<u8> {
    let arg = Encode!(&target, &method.to_string(), &inner, &cycles).unwrap();
    let reply = pic
        .update_call(proxy, anon(), "relay", arg)
        .unwrap_or_else(|e| panic!("relay {method}: {e:?}"));
    let raw = Decode!(&reply, Vec<u8>).expect("proxy returns raw reply bytes");
    assert!(!raw.is_empty(), "the {method} call itself was rejected");
    raw
}

/// Arm the mock with the next `getTransaction` reply and fold it with one paid
/// ingest, returning what the index recognized.
fn ingest(
    pic: &PocketIc,
    mock: Principal,
    proxy: Principal,
    index: Principal,
    reply: MultiGetTransactionResult,
    sig: &str,
) -> IngestResult {
    pic.update_call(
        mock,
        anon(),
        "set_reply",
        Encode!(&Encode!(&reply).unwrap()).unwrap(),
    )
    .expect("set_reply");
    let raw = relay(
        pic,
        proxy,
        index,
        "ingest",
        Encode!(&sig.to_string()).unwrap(),
        INGEST_PRICE,
    );
    Decode!(&raw, IngestResult).unwrap()
}

/// The whole IC-side flow, ending in a real threshold Ed25519 verdict signature
/// that verifies against the collection's resolver — everything but the Solana
/// claim, on a PocketIC replica.
#[test]
fn create_cancel_and_sign_a_real_verdict() {
    // Build the game wasm *before* the replica exists. The nested `cargo build` can
    // take a minute on a cold target dir, and an idle PocketIC instance gives up
    // waiting — a timeout that reads as a broken test rather than a slow one.
    let game_bytes = game_wasm();
    let (pic, index, mock, proxy) = setup();

    // Funding canister wired to THIS index + the replica root key.
    let root_key = pic.root_key().expect("nns root key");
    let app = pic.topology().get_app_subnets()[0];
    let game = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(game, 20_000_000_000_000);
    let init = Some(InitArgs {
        nns_root_key: root_key,
        index,
    });
    pic.install_canister(game, game_bytes, Encode!(&init).unwrap(), None);
    let b = pic
        .update_call(game, anon(), "bootstrap", Encode!().unwrap())
        .expect("bootstrap");
    assert!(matches!(
        Decode!(&b, CollectionResult).unwrap(),
        CollectionResult::KeyBootstrapped
    ));

    // Collection parameters. The recipient opens their own collection; the donor
    // funds the first contribution (its birth is what materializes the collection).
    let recipient_sk = SigningKey::from_bytes(&[5u8; 32]);
    let recipient = recipient_sk.verifying_key().to_bytes();
    let donor_sk = SigningKey::from_bytes(&[9u8; 32]);
    let donor = donor_sk.verifying_key().to_bytes();
    let recipient_nonce = 1u64;
    let duration = 100_000u64;
    let goal = 5_000_000u128;
    let gross = 2_000_000u64;
    let nonce = 7u64;
    // Far future (year ~2096): comfortably past the deadline rule's lower bound.
    let deadline = 4_000_000_000i64;

    let collection_id = protocol::collection_id(
        game.as_slice(),
        recipient,
        recipient_nonce,
        duration,
        VOTING_PERIOD,
        APPROVAL_THRESHOLD,
        QUORUM_WEIGHT,
    );
    let collection_hex = hex::encode(collection_id);

    // The per-collection resolver every escrow of the set must commit.
    let rq = pic
        .query_call(
            game,
            anon(),
            "get_resolver",
            Encode!(&collection_hex).unwrap(),
        )
        .expect("get_resolver");
    let resolver: [u8; 32] = bs58::decode(Decode!(&rq, Option<String>).unwrap().expect("resolver"))
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();

    // The escrow address the birth must live at (= what create re-derives).
    let salt = crown_salt::two_outcome::two_outcome(
        donor,
        recipient,
        gross,
        deadline,
        resolver,
        FEE_BPS,
        fee_wallet(),
        nonce,
    );
    let (escrow_arr, _) = crown_derive::solana_pda_address(factory(), &[b"escrow", &salt]).unwrap();
    let escrow = Pubkey::new_from_array(escrow_arr);

    // The collection's window anchors on the **birth slot**, not `now`
    // (`config::slot_to_created_at`), so the slot must map to a `created_at` that
    // is actually inside the funding window on this replica — otherwise the first
    // lazy tick finds it long expired and refunds it.
    //
    // The replica's clock is pinned relative to the *anchor* rather than read from
    // the host: the anchor is a devnet fact from a particular day, and a replica
    // booted before it would put every real slot below `GENESIS_SLOT`, where
    // `slot_to_created_at` is `None` and the collection dies as `CreatedAtOverflow`.
    // An hour past the anchor is unambiguously inside every window here.
    pic.set_time(Time::from_nanos_since_unix_epoch(
        (GENESIS_UNIX + 3_600) * 1_000_000_000,
    ));
    let now_secs = pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000;
    let created_at = now_secs - 60;
    let slot = GENESIS_SLOT + (created_at - GENESIS_UNIX) * 1_000 / SLOT_MS;
    assert_eq!(
        GENESIS_UNIX + (slot - GENESIS_SLOT) * SLOT_MS / 1_000,
        created_at,
        "the chosen slot must map back exactly (no rounding drift)"
    );

    // Inject the birth via the mock RPC + a paid ingest.
    let reply = consistent_reply(birth_tx(Pubkey::new_from_array(donor), escrow, salt), slot);
    pic.update_call(
        mock,
        anon(),
        "set_reply",
        Encode!(&Encode!(&reply).unwrap()).unwrap(),
    )
    .expect("set_reply");
    let ir = relay(
        &pic,
        proxy,
        index,
        "ingest",
        Encode!(&"sig-cf-1".to_string()).unwrap(),
        INGEST_PRICE,
    );
    assert!(
        matches!(
            Decode!(&ir, IngestResult).unwrap(),
            IngestResult::Applied { births: 1, .. }
        ),
        "ingest must fold exactly one birth"
    );

    // Certificate + birth witness for the create proof.
    let cq = pic
        .query_call(index, anon(), "get_certificate", Encode!().unwrap())
        .expect("get_certificate");
    let cert = Decode!(&cq, Option<Vec<u8>>, Vec<u8>)
        .unwrap()
        .0
        .expect("certificate present");
    let bq = pic
        .query_call(
            index,
            anon(),
            "get_birth",
            Encode!(&escrow_arr.to_vec()).unwrap(),
        )
        .expect("get_birth");
    let witness = Decode!(&bq, Option<BirthView>, Vec<u8>).unwrap().1;

    // A recipient-signed create + the unsigned birth-proof / field extras.
    let msg = protocol::create_message("devnet", &game.to_text(), &collection_hex, goal, duration);
    let extras = vec![
        ("recipient_nonce", recipient_nonce.to_string()),
        ("donor", bs58::encode(donor).into_string()),
        ("gross", gross.to_string()),
        ("deadline", deadline.to_string()),
        ("nonce", nonce.to_string()),
        ("witness", hex::encode(&witness)),
    ];
    let create_text = signed_request(&recipient_sk, &msg, &extras);

    // Before any root is pushed the witness has nothing to reconstruct into, so
    // the boundary refuses the very same request — for free, before any
    // replicated execution (`cost.md §6` #2).
    let early = pic.update_call(
        game,
        anon(),
        "create_collection",
        Encode!(&create_text).unwrap(),
    );
    assert!(
        early.is_err(),
        "no cached root → the boundary drops create_collection, it never executes"
    );

    // And a `create` with **no witness at all** is refused for the same reason,
    // which is the whole of the removed derivation echo (`P8`). It used to be
    // admitted and answered `Derived` — zero writes, but a full replicated
    // execution per copy, from a message the sender signs for themselves, i.e.
    // free and unbounded. Asserted here rather than in the update, because the
    // point is that it never reaches the update.
    let no_witness = signed_request(
        &recipient_sk,
        &msg,
        &extras
            .iter()
            .filter(|(k, _)| *k != "witness")
            .cloned()
            .collect::<Vec<_>>(),
    );
    assert!(
        pic.update_call(
            game,
            anon(),
            "create_collection",
            Encode!(&no_witness).unwrap()
        )
        .is_err(),
        "a proof-less create must die at the boundary, not execute replicated"
    );

    // Paid root refresh through the proxy (ingress carries no cycles).
    let before_root = pic.cycle_balance(game);
    let pr = relay(
        &pic,
        proxy,
        game,
        "push_root",
        Encode!(&cert).unwrap(),
        ROOT_PRICE,
    );
    assert!(
        matches!(
            Decode!(&pr, CollectionResult).unwrap(),
            CollectionResult::RootPushed
        ),
        "the index certificate authenticates a root"
    );
    assert_price_covers_the_work(
        "push_root",
        before_root,
        pic.cycle_balance(game),
        ROOT_PRICE,
    );

    // Create as a **direct ingress** — what a real recipient wallet sends. This is
    // the boundary contract: with the certificate's BLS moved to `push_root`, the
    // witness walk fits `inspect_message`, so the call is admitted and executes.
    let rr = pic
        .update_call(
            game,
            anon(),
            "create_collection",
            Encode!(&create_text).unwrap(),
        )
        .expect("direct ingress create must be admitted");
    let res = Decode!(&rr, CollectionResult).unwrap();
    assert!(
        matches!(res, CollectionResult::Materialized),
        "create must materialize the collection: {res:?}"
    );

    // The collection now exists (Funding).
    let cq = pic
        .query_call(
            game,
            anon(),
            "get_collection",
            Encode!(&collection_hex).unwrap(),
        )
        .expect("get_collection");
    let view = Decode!(&cq, Option<conditional_funding::CollectionView>)
        .unwrap()
        .expect("the collection is materialized");
    assert!(matches!(view.state, CollectionStateView::Funding));
    // The window a donor has to size their escrow `deadline` against. Asserted
    // because this is the *only* place it is published: `collection_id` is a hash,
    // and every contribution after the one that materialized the collection joins
    // by deriving the resolver, never presenting itself here (spec §Тайминги).
    assert_eq!(
        view.created_at, created_at,
        "the birth slot, through the anchor"
    );
    assert_eq!(view.duration, duration);
    assert_eq!(view.voting_period, VOTING_PERIOD);
    assert_eq!(
        view.recipient,
        bs58::encode(recipient).into_string(),
        "a contribution's escrow salt commits the recipient"
    );

    // Recipient cancels → the collection is Decided{Refund} (all-or-nothing: the
    // whole set refunds).
    let cancel_msg = protocol::cancel_message("devnet", &game.to_text(), &collection_hex);
    let cancel_text = signed_request(&recipient_sk, &cancel_msg, &[]);
    let dr = pic
        .update_call(
            game,
            anon(),
            "recipient_cancel",
            Encode!(&cancel_text).unwrap(),
        )
        .expect("recipient_cancel admitted");
    assert!(
        matches!(
            Decode!(&dr, CollectionResult).unwrap(),
            CollectionResult::Advanced(CollectionStateView::DecidedRefund)
        ),
        "recipient_cancel decides the collection as Refund"
    );

    // Paid request_signature → a real threshold Ed25519 `Signed{Refund}` verdict.
    let before_sign = pic.cycle_balance(game);
    let sr = relay(
        &pic,
        proxy,
        game,
        "request_signature",
        Encode!(&"devnet".to_string(), &collection_hex).unwrap(),
        SIGN_PRICE,
    );
    let signature = match Decode!(&sr, CollectionResult).unwrap() {
        CollectionResult::Signed { outcome, signature } => {
            assert_eq!(outcome, 1, "refund outcome");
            assert_eq!(signature.len(), 64, "a 64-byte Ed25519 signature");
            signature
        }
        other => panic!("expected Signed{{Refund}}, got {other:?}"),
    };
    assert_price_covers_the_work(
        "request_signature",
        before_sign,
        pic.cycle_balance(game),
        SIGN_PRICE,
    );

    // The signature is a valid Ed25519 signature over the verdict message
    // `VERDICT_DOMAIN ‖ program_id(32) ‖ outcome` for the collection's resolver —
    // exactly what Solana's ed25519 program (and the two-outcome `claim`'s
    // `assert_resolver_signed`) checks. Verifying it here proves the on-chain claim
    // would accept it. This is the cross-chain link, D8.
    let mut verdict = b"crown:two-outcome:devnet".to_vec();
    verdict.extend_from_slice(&factory()); // program_id == crate::ID == config::FACTORY
    verdict.push(1u8); // refund
    verdict.extend_from_slice(&FEE_BPS.to_le_bytes());
    verdict.extend_from_slice(&fee_wallet());
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&resolver)
        .expect("resolver is a valid Ed25519 public key");
    let sig = ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature");
    vk.verify_strict(&verdict, &sig)
        .expect("the threshold verdict signature verifies against the resolver");

    // The signature is memoized: a second request is served from store, free —
    // this is what makes the `s/N` amortization a fact, not a possibility
    // (spec §Методы `get_signature`, `cost.md §6` #5). Zero cycles attached.
    let again = relay(
        &pic,
        proxy,
        game,
        "request_signature",
        Encode!(&"devnet".to_string(), &collection_hex).unwrap(),
        0,
    );
    match Decode!(&again, CollectionResult).unwrap() {
        CollectionResult::Signed {
            outcome,
            signature: s2,
        } => {
            assert_eq!(outcome, 1);
            assert_eq!(s2, signature, "the very same bytes, for free");
        }
        other => panic!("a repeat must be served from store for free, got {other:?}"),
    }

    // And the free query hands the same bytes to every other escrow of the set.
    let gq = pic
        .query_call(
            game,
            anon(),
            "get_signature",
            Encode!(&collection_hex).unwrap(),
        )
        .expect("get_signature");
    let view = Decode!(&gq, Option<conditional_funding::SignatureView>)
        .unwrap()
        .expect("signature is stored");
    assert_eq!(view.outcome, 1);
    assert_eq!(view.signature, signature);
}

/// The path a collection is actually decided by — `ready` → a quorate,
/// reputation-weighted `vote` → the window closes → a real threshold signature.
/// `recipient_cancel` above is the shortcut; this is the vote.
///
/// **Two collections, and that is the point.** With the verdict default flipped in
/// the recipient's favour (`LOGIC_VERSION` 4: silence, a tie and an inquorate vote
/// all settle), a lone settle case is vacuously green — it passes with the ballot
/// uncounted, because doing nothing settles too. The second collection is voted
/// `not_done` by the same voter with the same weight and must come out `Refund`.
/// Only the pair can go red in its own case (`P7.13`), and only the pair shows the
/// quorum gate and the approval share doing their two different jobs.
///
/// Until this test, `ready` and `vote` were only ever exercised by the live devnet
/// driver (`e2e/f5`), which needs money and does not run in CI.
#[test]
fn a_quorate_vote_decides_a_collection_both_ways() {
    let game_bytes = game_wasm();
    let (pic, index, mock, proxy) = setup();

    let root_key = pic.root_key().expect("nns root key");
    let app = pic.topology().get_app_subnets()[0];
    let game = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(game, 40_000_000_000_000);
    let init = Some(InitArgs {
        nns_root_key: root_key,
        index,
    });
    pic.install_canister(game, game_bytes, Encode!(&init).unwrap(), None);
    let b = pic
        .update_call(game, anon(), "bootstrap", Encode!().unwrap())
        .expect("bootstrap");
    assert!(matches!(
        Decode!(&b, CollectionResult).unwrap(),
        CollectionResult::KeyBootstrapped
    ));
    // `bootstrap` is admitted only while the master key is missing (spec §Граница).
    // The very same call that just succeeded is now dropped at the boundary — for
    // free, before any replicated execution — so a one-shot setup method cannot be
    // turned into an unbounded free `update` by replaying it.
    assert!(
        pic.update_call(game, anon(), "bootstrap", Encode!().unwrap())
            .is_err(),
        "a repeat bootstrap must be dropped once the key is taken"
    );

    let recipient_sk = SigningKey::from_bytes(&[5u8; 32]);
    let recipient = recipient_sk.verifying_key().to_bytes();
    let donor_sk = SigningKey::from_bytes(&[9u8; 32]);
    let donor = donor_sk.verifying_key().to_bytes();
    // A third wallet: it holds reputation *at this recipient* and contributes
    // nothing. Weight is local to the recipient (`00 §10.1`).
    let voter_sk = SigningKey::from_bytes(&[3u8; 32]);
    let voter = voter_sk.verifying_key().to_bytes();

    let duration = 100_000u64;
    let goal = 5_000_000u128;
    let gross = 2_000_000u64;
    let deadline = 4_000_000_000i64; // far future; the vote window is the clock here

    // Same pinning as the cancel path above: the collection's window anchors on the
    // birth **slot**, so the replica clock is set relative to the config anchor.
    pic.set_time(Time::from_nanos_since_unix_epoch(
        (GENESIS_UNIX + 3_600) * 1_000_000_000,
    ));
    let now_secs = pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000;
    let created_at = now_secs - 60;
    let slot = GENESIS_SLOT + (created_at - GENESIS_UNIX) * 1_000 / SLOT_MS;

    // The two collections differ **only** in `recipient_nonce` (which just spreads
    // the id) and in how the voter votes. Same recipient, contribution and window.
    let cases: [(u64, u64, &str, u8, &str); 2] = [
        (1, 7, "done", 0, "sig-cf-settle"),
        (2, 8, "not_done", 1, "sig-cf-refund"),
    ];

    let mut derived = Vec::new();
    for (recipient_nonce, nonce, choice, outcome, birth_sig) in cases {
        let collection_id = protocol::collection_id(
            game.as_slice(),
            recipient,
            recipient_nonce,
            duration,
            VOTING_PERIOD,
            APPROVAL_THRESHOLD,
            QUORUM_WEIGHT,
        );
        let collection_hex = hex::encode(collection_id);

        let rq = pic
            .query_call(
                game,
                anon(),
                "get_resolver",
                Encode!(&collection_hex).unwrap(),
            )
            .expect("get_resolver");
        let resolver: [u8; 32] =
            bs58::decode(Decode!(&rq, Option<String>).unwrap().expect("resolver"))
                .into_vec()
                .unwrap()
                .try_into()
                .unwrap();

        let salt = crown_salt::two_outcome::two_outcome(
            donor,
            recipient,
            gross,
            deadline,
            resolver,
            FEE_BPS,
            fee_wallet(),
            nonce,
        );
        let (escrow_arr, _) =
            crown_derive::solana_pda_address(factory(), &[b"escrow", &salt]).unwrap();

        let r = ingest(
            &pic,
            mock,
            proxy,
            index,
            consistent_reply(
                birth_tx(
                    Pubkey::new_from_array(donor),
                    Pubkey::new_from_array(escrow_arr),
                    salt,
                ),
                slot,
            ),
            birth_sig,
        );
        assert!(
            matches!(r, IngestResult::Applied { births: 1, .. }),
            "collection {recipient_nonce}: the birth must fold: {r:?}"
        );

        derived.push((
            recipient_nonce,
            nonce,
            choice,
            outcome,
            collection_hex,
            resolver,
            escrow_arr,
        ));
    }

    // ---- the voter buys its weight: one real settlement, folded by the index ----
    // Above the index's dust floor ($0.20) **and** above `quorum_weight`, or the
    // ballot would be inquorate — and an inquorate vote no longer refunds anything,
    // it settles, which would make the `not_done` case pass for the wrong reason.
    let weight_gross = 500_000u64;
    let r = ingest(
        &pic,
        mock,
        proxy,
        index,
        consistent_reply(
            settlement_tx(Pubkey::new_from_array(voter), recipient, weight_gross),
            slot + 1,
        ),
        "sig-cf-weight",
    );
    assert!(
        matches!(
            r,
            IngestResult::Applied {
                settlements: 1,
                anomalies: 0,
                ..
            }
        ),
        "the voter's donation must fold into reputation: {r:?}"
    );

    let chain = conditional_funding::field::chain_id("devnet");
    let repq = pic
        .query_call(
            index,
            anon(),
            "get_reputation",
            Encode!(&chain.to_vec(), &voter.to_vec(), &recipient.to_vec()).unwrap(),
        )
        .expect("get_reputation");
    let (weight, weight_witness) = Decode!(&repq, candid::Nat, Vec<u8>).unwrap();
    assert_eq!(
        weight,
        candid::Nat::from(weight_gross),
        "the book credits the voter at this recipient"
    );
    assert!(
        u128::from(weight_gross) >= QUORUM_WEIGHT,
        "one voter must carry the quorum, or the vote decides nothing"
    );

    // ---- one paid root refresh covers every proof above ----
    let cq = pic
        .query_call(index, anon(), "get_certificate", Encode!().unwrap())
        .expect("get_certificate");
    let cert = Decode!(&cq, Option<Vec<u8>>, Vec<u8>)
        .unwrap()
        .0
        .expect("certificate present");
    let pr = relay(
        &pic,
        proxy,
        game,
        "push_root",
        Encode!(&cert).unwrap(),
        ROOT_PRICE,
    );
    assert!(
        matches!(
            Decode!(&pr, CollectionResult).unwrap(),
            CollectionResult::RootPushed
        ),
        "the index certificate authenticates a root"
    );

    // ---- create → ready → vote, both collections, direct ingress ----
    for (recipient_nonce, nonce, choice, _outcome, collection_hex, _resolver, escrow_arr) in
        &derived
    {
        let bq = pic
            .query_call(
                index,
                anon(),
                "get_birth",
                Encode!(&escrow_arr.to_vec()).unwrap(),
            )
            .expect("get_birth");
        let witness = Decode!(&bq, Option<BirthView>, Vec<u8>).unwrap().1;

        let msg =
            protocol::create_message("devnet", &game.to_text(), collection_hex, goal, duration);
        let extras = vec![
            ("recipient_nonce", recipient_nonce.to_string()),
            ("donor", bs58::encode(donor).into_string()),
            ("gross", gross.to_string()),
            ("deadline", deadline.to_string()),
            ("nonce", nonce.to_string()),
            ("witness", hex::encode(&witness)),
        ];
        let cr = pic
            .update_call(
                game,
                anon(),
                "create_collection",
                Encode!(&signed_request(&recipient_sk, &msg, &extras)).unwrap(),
            )
            .expect("create must be admitted");
        assert!(
            matches!(
                Decode!(&cr, CollectionResult).unwrap(),
                CollectionResult::Materialized
            ),
            "collection {recipient_nonce}: create must materialize"
        );

        let ready_text = signed_request(
            &recipient_sk,
            &protocol::ready_message("devnet", &game.to_text(), collection_hex),
            &[],
        );

        // Size is cut **first**, before anything is parsed (`MAX_ARG_BYTES` = 8 KiB).
        // Padded with an unsigned extra the parser would otherwise ignore, so this
        // request is valid in every other respect — the *only* reason it dies is its
        // length, and the unpadded twin below proves it by being admitted.
        let padded = format!("{ready_text}\npadding: {}", "x".repeat(9_000));
        assert!(
            padded.len() > 8 * 1024,
            "the padded request has to actually exceed the cap"
        );
        assert!(
            pic.update_call(game, anon(), "ready", Encode!(&padded).unwrap())
                .is_err(),
            "collection {recipient_nonce}: an oversized ingress must be dropped before it is parsed"
        );

        let rr = pic
            .update_call(game, anon(), "ready", Encode!(&ready_text).unwrap())
            .expect("ready admitted");
        assert!(
            matches!(
                Decode!(&rr, CollectionResult).unwrap(),
                CollectionResult::Advanced(CollectionStateView::Voting)
            ),
            "collection {recipient_nonce}: ready must open the voting window"
        );

        // Byte-identical replay of a now-doomed action. The signed half carries no
        // nonce, so one observed valid message is a flood template; the boundary
        // refuses it by **state**, not just by signer, and the canister is never
        // billed for the round (`cost.md §6` #2).
        assert!(
            pic.update_call(game, anon(), "ready", Encode!(&ready_text).unwrap())
                .is_err(),
            "collection {recipient_nonce}: a second ready is doomed and must die at the boundary"
        );

        // The ballot. Its weight is proven, not asserted: a hash-tree walk over the
        // reputation witness against the root pushed above — the same path
        // `inspect_message` ran to admit this very call.
        // `v` — the price of one vote, the last unmeasured входная цена of the
        // model (`cost.md §1` carried an estimate of ~15e6). Measured here rather
        // than assumed: a vote is the only path with no fee behind it, so if it
        // costs more than the model says, every scope quietly runs at a loss in
        // proportion to how popular it was.
        let before_vote = pic.cycle_balance(game);
        let vr = pic
            .update_call(
                game,
                anon(),
                "vote",
                Encode!(&signed_request(
                    &voter_sk,
                    &protocol::vote_message("devnet", &game.to_text(), collection_hex, choice),
                    &[("weight_witness", hex::encode(&weight_witness))]
                ))
                .unwrap(),
            )
            .unwrap_or_else(|e| {
                panic!("collection {recipient_nonce}: a weight-proven vote must be admitted: {e:?}")
            });
        println!(
            "[cost] vote: {} cycles",
            before_vote.saturating_sub(pic.cycle_balance(game))
        );
        assert!(
            matches!(
                Decode!(&vr, CollectionResult).unwrap(),
                CollectionResult::Advanced(CollectionStateView::Voting)
            ),
            "collection {recipient_nonce}: the vote is recorded and the window stays open"
        );
    }

    // ---- the window closes on its own: no timer, a pure function of the clock ----
    pic.advance_time(std::time::Duration::from_secs(VOTING_PERIOD + 1));
    pic.tick();

    for (recipient_nonce, _, choice, outcome, collection_hex, resolver, _) in &derived {
        let cq = pic
            .query_call(
                game,
                anon(),
                "get_collection",
                Encode!(collection_hex).unwrap(),
            )
            .expect("get_collection");
        let got = Decode!(&cq, Option<conditional_funding::CollectionView>)
            .unwrap()
            .expect("the tally is lazy but total — reading past the window decides")
            .state;
        let decided_as_expected = matches!(
            (*outcome, got),
            (0, CollectionStateView::DecidedSettle) | (1, CollectionStateView::DecidedRefund)
        );
        assert!(
            decided_as_expected,
            "collection {recipient_nonce}: a quorate `{choice}` vote must decide outcome {outcome}, got {got:?}"
        );

        let sr = relay(
            &pic,
            proxy,
            game,
            "request_signature",
            Encode!(&"devnet".to_string(), collection_hex).unwrap(),
            SIGN_PRICE,
        );
        let signature = match Decode!(&sr, CollectionResult).unwrap() {
            CollectionResult::Signed {
                outcome: got_outcome,
                signature,
            } => {
                assert_eq!(
                    got_outcome, *outcome,
                    "collection {recipient_nonce}: signed outcome"
                );
                assert_eq!(signature.len(), 64, "a 64-byte Ed25519 signature");
                signature
            }
            other => panic!("collection {recipient_nonce}: expected Signed, got {other:?}"),
        };

        // What Solana's ed25519 program (and `two-outcome`'s `assert_resolver_signed`)
        // checks — one signature per collection, reused by every escrow of the set.
        let mut verdict = b"crown:two-outcome:devnet".to_vec();
        verdict.extend_from_slice(&factory());
        verdict.push(*outcome);
        verdict.extend_from_slice(&FEE_BPS.to_le_bytes());
        verdict.extend_from_slice(&fee_wallet());
        let vk = ed25519_dalek::VerifyingKey::from_bytes(resolver)
            .expect("resolver is a valid Ed25519 public key");
        let sig = ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature");
        vk.verify_strict(&verdict, &sig).unwrap_or_else(|e| {
            panic!("collection {recipient_nonce}: the verdict signature must verify: {e:?}")
        });
    }
}
