//! Full canister-game e2e (PocketIC): the birth-proof / voting / signing path that
//! needs a real index + threshold key, without a live Solana RPC outcall.
//!
//! A mock SOL RPC canister at the index's pinned `SOL_RPC` principal serves
//! synthetic-but-real-shaped transactions, so a paid `ingest` (fronted by the relay
//! proxy with cycles) folds them into a **birth** and into **reputation**. From
//! there the three tests below cover, in order:
//!
//!   1. the index's recognition path alone — `create_escrow` → birth;
//!   2. `register_task` → `decline` → `request_signature` → `Signed{Cancel}`;
//!   3. `accept` → `ready` → a weighted `vote` → the window closes →
//!      `Signed{Settle}`, and the same flow voted the other way → `Signed{Cancel}`.
//!
//! Every terminal outcome the game can reach is produced here on a replica, and
//! every signature is verified against the task's resolver — the same check the
//! two-outcome `claim` makes on chain. What is still out of reach: the money
//! movement itself (that is `two-outcome/tests/claim.rs` and the live `T5`) and
//! the multi-provider RPC consensus, which does not exist off IC mainnet.
//!
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic cargo test --test full_e2e

use candid::{CandidType, Decode, Deserialize, Encode, Principal, Reserved};
use conditional_tasks::{protocol, InitArgs, TaskResult, TaskStateView};
use ed25519_dalek::{Signer, SigningKey};
use pocket_ic::{PocketIc, PocketIcBuilder};
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    transaction::Transaction,
};

const GAME_WASM: &str = "../target/e2e/wasm32-unknown-unknown/release/conditional_tasks.wasm";
const VOTING_PERIOD: u64 = 120; // config::VOTING_PERIOD (testnet profile)
                                // The fee is the game's price list, not a request field (harness §9): these are
                                // `config::FEE_BPS` / `config::FEE_WALLET` of the testnet profile, and the escrow
                                // must be born with exactly them or it derives to a different address.
const FEE_BPS: u16 = 300;
const FEE_WALLET_B58: &str = "FS6ZNuPxXqWSGzwXEQpfoxikDksbEzmrXGZDFXmFj6vS";
const SEP: &str = "\n---\n";
/// `conditional_tasks_logic::DEADLINE_MARGIN` (72 h). The logic crate is a
/// dependency of the canister, not of this test binary, so the value is copied
/// like `VOTING_PERIOD` above — it is what turns a `deadline` into a `voting_end`.
const DEADLINE_MARGIN: i64 = 259_200;
/// `conditional_tasks_logic::MIN_VOTE_WEIGHT` — a lighter vote never counts.
const MIN_VOTE_WEIGHT: u128 = 100_000;
/// `config::MIN_GROSS` of the **testnet** profile — the game floor a registration
/// must clear. Copied like `VOTING_PERIOD` above (config is baked into the wasm,
/// not visible to this test binary), so it has to be re-copied whenever
/// `config/testnet.toml` moves: the sub-floor case below is `MIN_GROSS - 1`, and
/// a stale value here stops being sub-floor and the test fails on the *right*
/// behaviour. Mainnet's floor is `2_200_000` and is deliberately not this number
/// (`cost.md §6`: devnet floors are dropped so a live run costs cents).
const MIN_GROSS: u64 = 250_000;

fn b58_32(s: &str) -> [u8; 32] {
    bs58::decode(s).into_vec().unwrap().try_into().unwrap()
}

fn fee_wallet() -> [u8; 32] {
    b58_32(FEE_WALLET_B58)
}

/// Build the conditional-tasks wasm into an isolated target dir — not to select a
/// profile (there is one devnet profile, `testnet`, and it names the key the
/// replica actually provisions), but so this nested `cargo build` never contends
/// with the outer `cargo test` for the workspace build lock.
///
/// Always invoked, never skipped on "the file is already there": these bytes
/// depend on `config/testnet.toml`, and an artifact cached from an earlier
/// config silently disagrees with the ids this test derives. A stale `fee_wallet`
/// alone moves every escrow address, so the birth proof lands nowhere and the
/// boundary drops a perfectly valid `register_task` with nothing to read but
/// "rejected" — which is exactly how this was found. Cargo no-ops when nothing
/// changed, so the guard costs nothing.
fn tasks_game_wasm() -> Vec<u8> {
    {
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "-p",
                "conditional-tasks",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "--target-dir",
                "../target/e2e",
            ])
            .status()
            .expect("build conditional-tasks wasm");
        assert!(status.success());
    }
    std::fs::read(GAME_WASM).expect("read conditional-tasks wasm")
}

/// `<message>\n---\npubkey: ..\nsignature: ..\n<extras>` (tasks request wire format).
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
// candid types (variant/field names match the index's `#[serde(rename)]`s, so this
// encodes/decodes compatibly). Copied rather than imported so the test binary does
// not link the index canister (duplicate `canister_init` symbols).
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

/// Non-negativity, **measured rather than promised** (`cost.md §6`,
/// `01-standards §Тесты 4,12`). A paid pull must leave the canister no poorer than
/// it found it: it takes `price` in and spends execution (plus, for the signature,
/// the threshold fee the management canister charges *us*). So the balance delta
/// across the call has to be >= 0, and what is left of `price` is the margin.
///
/// Until this existed, "`SIGN_PRICE` >= measured `sign_with_schnorr`" and
/// "`ROOT_PRICE` >= two BLS pairings" were sentences in `cost.md` with nothing
/// executing them: both are baked constants, and a config edit that dropped either
/// below cost would have gone green all the way to mainnet, where the symptom is a
/// slow cycle leak rather than a failure.
///
/// **What it is not:** a mainnet number. PocketIC runs a 13-node application
/// subnet; the games live on a 34-node fiduciary one, where execution and the
/// threshold signature cost roughly 2.6x more. So this is a floor — it catches a
/// price set below even the cheap subnet's cost. The mainnet figure stays a
/// cost-gate measurement (`07-build-plan §P8`), and the margin printed here is
/// what that gate compares against.
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

// ---- Reputation: what a vote actually weighs ----
//
// A vote weighs the voter's book reputation to the task's recipient, and the only
// way into the book is an honest settlement read from chain (`00 §9`). The index
// recognizes one when a `Settled` event-CPI of the **pinned splitter** is
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
/// Returned base58-encoded, as the SOL RPC would.
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

/// Anchor discriminator: `sha256("global:create_escrow")[0..8]` — matches what the
/// index computes and what the two-outcome program's `create_escrow` emits.
fn create_escrow_disc() -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"global:create_escrow");
    let d = h.finalize();
    let mut o = [0u8; 8];
    o.copy_from_slice(&d[0..8]);
    o
}

/// A synthetic `create_escrow` transaction for `(donor, escrow)` that the index
/// recognizes as a birth (`escrow == PDA(factory, [b"escrow", salt])`, disc + salt
/// are the only fields it reads). Returned base58-encoded, as the SOL RPC would.
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
/// Ingress carries no cycles, so every paid call goes through the proxy fixture.
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

#[test]
fn ingest_folds_a_mocked_create_escrow_into_a_birth() {
    let (pic, index, mock, proxy) = setup();

    // A synthetic birth: random donor, a genuine factory PDA from a random salt.
    let donor = Pubkey::new_unique();
    let salt = [7u8; 32];
    let (escrow_arr, _) = crown_derive::solana_pda_address(factory(), &[b"escrow", &salt]).unwrap();
    let escrow = Pubkey::new_from_array(escrow_arr);

    // Preload the mock's `getTransaction` reply.
    let reply = consistent_reply(birth_tx(donor, escrow, salt), 424_242);
    pic.update_call(
        mock,
        anon(),
        "set_reply",
        Encode!(&Encode!(&reply).unwrap()).unwrap(),
    )
    .expect("set_reply");

    // Paid ingest through the relay proxy (ingress carries no cycles).
    let sig = "sig-birth-1".to_string();
    let inner = Encode!(&sig).unwrap();
    let arg = Encode!(&index, &"ingest".to_string(), &inner, &INGEST_PRICE).unwrap();
    let raw_reply = pic
        .update_call(proxy, anon(), "relay", arg)
        .expect("relay ingest");
    let raw = Decode!(&raw_reply, Vec<u8>).unwrap();
    assert!(!raw.is_empty(), "the ingest call itself was rejected");
    let result = Decode!(&raw, IngestResult).unwrap();
    assert!(
        matches!(result, IngestResult::Applied { births: 1, .. }),
        "ingest must fold exactly one birth: {result:?}"
    );

    // The index now certifies the birth at the escrow address.
    let q = pic
        .query_call(
            index,
            anon(),
            "get_birth",
            Encode!(&escrow.to_bytes().to_vec()).unwrap(),
        )
        .expect("get_birth");
    let (bv, witness) = Decode!(&q, Option<BirthView>, Vec<u8>).unwrap();
    let bv = bv.expect("a birth is recorded at the escrow address");
    assert_eq!(bv.donor, donor.to_bytes().to_vec(), "donor matches");
    assert_eq!(bv.slot, 424_242, "slot matches the tx meta");
    assert!(!witness.is_empty(), "a birth witness is returned");
}

/// Milestone 3+4: the birth in the index is consumed by `register_task` (a real
/// donor-signed request + cert + witness) → materialize; then `decline` →
/// `request_signature` produces a real threshold `Signed{Cancel}` verdict for the
/// escrow's resolver. Everything but the Solana claim, on a PocketIC replica.
#[test]
fn register_decline_and_sign_a_real_verdict() {
    // Build the game wasm *before* the replica exists. The nested `cargo build` can
    // take a minute on a cold target dir, and an idle PocketIC instance gives up
    // waiting — a timeout that reads as a broken test rather than a slow one.
    let game_bytes = tasks_game_wasm();
    let (pic, index, mock, proxy) = setup();

    // Tasks canister wired to THIS index + the replica root key.
    let root_key = pic.root_key().expect("nns root key");
    let app = pic.topology().get_app_subnets()[0];
    let tasks = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(tasks, 20_000_000_000_000);
    let init = Some(InitArgs {
        nns_root_key: root_key,
        index,
    });
    pic.install_canister(tasks, game_bytes, Encode!(&init).unwrap(), None);
    let b = pic
        .update_call(tasks, anon(), "bootstrap", Encode!().unwrap())
        .expect("bootstrap");
    assert!(matches!(
        Decode!(&b, TaskResult).unwrap(),
        TaskResult::KeyBootstrapped
    ));

    // Task parameters. The donor's wallet is an ed25519 keypair (also its Solana id).
    let donor = SigningKey::from_bytes(&[9u8; 32]);
    let donor_pk = donor.verifying_key().to_bytes();
    // The recipient is a real keypair so it can sign its own `decline`.
    let recipient_sk = SigningKey::from_bytes(&[5u8; 32]);
    let recipient = recipient_sk.verifying_key().to_bytes();
    let gross = 2_000_000u64;
    let nonce = 1u64;
    let duration = 100_000u64;
    // Far future (year ~2096): comfortably past `now + duration + voting_period +
    // margin` for PocketIC's genesis time — the deadline rule is a lower bound only.
    let deadline = 4_000_000_000i64;
    let task_id = protocol::task_id(
        tasks.as_slice(),
        donor_pk,
        recipient,
        gross,
        deadline,
        FEE_BPS,
        fee_wallet(),
        nonce,
        duration,
        VOTING_PERIOD,
    );
    let task_bs58 = bs58::encode(task_id).into_string();

    // The per-task resolver the escrow must commit (from the bootstrapped canister).
    let rq = pic
        .query_call(tasks, anon(), "get_resolver", Encode!(&task_bs58).unwrap())
        .expect("get_resolver");
    let resolver: [u8; 32] = bs58::decode(Decode!(&rq, Option<String>).unwrap().expect("resolver"))
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();

    // The escrow address the birth must live at (= what register re-derives).
    let salt = crown_salt::two_outcome::two_outcome(
        donor_pk,
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

    // Inject the birth via the mock RPC + a paid ingest.
    let reply = consistent_reply(
        birth_tx(Pubkey::new_from_array(donor_pk), escrow, salt),
        555,
    );
    pic.update_call(
        mock,
        anon(),
        "set_reply",
        Encode!(&Encode!(&reply).unwrap()).unwrap(),
    )
    .expect("set_reply");
    let inner = Encode!(&"sig-reg-1".to_string()).unwrap();
    let arg = Encode!(&index, &"ingest".to_string(), &inner, &INGEST_PRICE).unwrap();
    let ir = pic
        .update_call(proxy, anon(), "relay", arg)
        .expect("relay ingest");
    assert!(matches!(
        Decode!(&Decode!(&ir, Vec<u8>).unwrap(), IngestResult).unwrap(),
        IngestResult::Applied { births: 1, .. }
    ));

    // Certificate + birth witness for the register proof.
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

    // A donor-signed register request + the unsigned birth-proof / field extras.
    let text_hash = [0xabu8; 32];
    let msg = protocol::register_message(
        "devnet",
        &tasks.to_text(),
        &task_bs58,
        &hex::encode(text_hash),
        duration,
    );
    let extras = vec![
        ("recipient", bs58::encode(recipient).into_string()),
        ("gross", gross.to_string()),
        ("deadline", deadline.to_string()),
        ("nonce", nonce.to_string()),
        ("witness", hex::encode(&witness)),
    ];
    let register_text = signed_request(&donor, &msg, &extras);

    // Before any root is pushed the witness has nothing to reconstruct into, so
    // the boundary refuses the very same request — for free, before any
    // replicated execution (`cost.md §6` #2).
    let early = pic.update_call(
        tasks,
        anon(),
        "register_task",
        Encode!(&register_text).unwrap(),
    );
    assert!(
        early.is_err(),
        "no cached root → the boundary drops register, it never executes"
    );

    // Paid root refresh through the proxy (ingress carries no cycles).
    let root_arg = Encode!(
        &tasks,
        &"push_root".to_string(),
        &Encode!(&cert).unwrap(),
        &1_000_000_000u128
    )
    .unwrap();
    let pr = pic
        .update_call(proxy, anon(), "relay", root_arg)
        .expect("relay push_root");
    assert!(
        matches!(
            Decode!(&Decode!(&pr, Vec<u8>).unwrap(), TaskResult).unwrap(),
            TaskResult::RootPushed
        ),
        "the index certificate authenticates a root"
    );

    // The fee is the game's price list, not the donor's (harness §9). A donor who
    // bakes `fee_wallet = self` into the escrow and presents the matching `task_id`
    // is refused: the canister recomputes the id with `config::FEE_BPS/FEE_WALLET`,
    // so a self-dealt fee can never reach a paid verdict signature. Rejected either
    // at the boundary or by the update — both are the contract (harness §6).
    let stolen_id = protocol::task_id(
        tasks.as_slice(),
        donor_pk,
        recipient,
        gross,
        deadline,
        0,        // fee_bps: no fee at all
        donor_pk, // fee_wallet: the donor's own wallet
        nonce,
        duration,
        VOTING_PERIOD,
    );
    let stolen_msg = protocol::register_message(
        "devnet",
        &tasks.to_text(),
        &bs58::encode(stolen_id).into_string(),
        &hex::encode(text_hash),
        duration,
    );
    let stolen_text = signed_request(&donor, &stolen_msg, &extras);
    // Either half of the rule is a pass: the boundary drops it (`Err`), or the
    // replicated `update` refuses it as a mismatch. Both mean a self-dealt fee
    // never derives to a task this canister will accept.
    if let Ok(bytes) = pic.update_call(
        tasks,
        anon(),
        "register_task",
        Encode!(&stolen_text).unwrap(),
    ) {
        assert!(
            matches!(
                Decode!(&bytes, TaskResult).unwrap(),
                TaskResult::TaskIdMismatch
            ),
            "a self-dealt fee must not derive to a task the canister accepts"
        );
    }

    // Register as a **direct ingress** — what a real donor wallet sends. This is
    // the boundary contract: with the certificate's BLS moved to `push_root`, the
    // witness walk fits `inspect_message`, so the call is admitted and executes.
    let rr = pic
        .update_call(
            tasks,
            anon(),
            "register_task",
            Encode!(&register_text).unwrap(),
        )
        .expect("direct ingress register must be admitted");
    let res = Decode!(&rr, TaskResult).unwrap();
    assert!(
        matches!(res, TaskResult::Materialized),
        "register must materialize the task: {res:?}"
    );

    // The task now exists (Created).
    let tq = pic
        .query_call(tasks, anon(), "get_task", Encode!(&task_bs58).unwrap())
        .expect("get_task");
    assert!(Decode!(&tq, Option<TaskStateView>).unwrap().is_some());

    // ---- the clock-free half of the registration policy lives at the boundary ----
    //
    // A registration below the game floor is doomed **permanently**: `gross` is
    // committed by `task_id` against an escrow that cannot change, and no passage
    // of time turns the refusal into an acceptance. Until `P8` the floor was
    // checked only in the update, so such a call was *admitted* — it came back
    // `GrossBelowFloor` after a full replicated execution — and it never
    // materialized, so `is_materialized` never began to refuse it either. With no
    // nonce in the signed half of a request, that one message was a flood
    // template: free to replay, billed to this canister, forever.
    //
    // This is the only shape that can tell the fix from its absence, which is why
    // it costs a second birth: the request must carry a **valid** proof and still
    // be doomed. Anything cheaper (a bad witness, no cached root) is dropped by a
    // check that was already there.
    let low_gross = MIN_GROSS - 1;
    let low_nonce = 2u64;
    let low_id = protocol::task_id(
        tasks.as_slice(),
        donor_pk,
        recipient,
        low_gross,
        deadline,
        FEE_BPS,
        fee_wallet(),
        low_nonce,
        duration,
        VOTING_PERIOD,
    );
    let low_bs58 = bs58::encode(low_id).into_string();
    let rq = pic
        .query_call(tasks, anon(), "get_resolver", Encode!(&low_bs58).unwrap())
        .expect("get_resolver");
    let low_resolver: [u8; 32] =
        bs58::decode(Decode!(&rq, Option<String>).unwrap().expect("resolver"))
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
    let low_salt = crown_salt::two_outcome::two_outcome(
        donor_pk,
        recipient,
        low_gross,
        deadline,
        low_resolver,
        FEE_BPS,
        fee_wallet(),
        low_nonce,
    );
    let (low_escrow, _) =
        crown_derive::solana_pda_address(factory(), &[b"escrow", &low_salt]).unwrap();
    let reply = consistent_reply(
        birth_tx(
            Pubkey::new_from_array(donor_pk),
            Pubkey::new_from_array(low_escrow),
            low_salt,
        ),
        556,
    );
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
        Encode!(&"sig-reg-low".to_string()).unwrap(),
        INGEST_PRICE,
    );
    assert!(matches!(
        Decode!(&ir, IngestResult).unwrap(),
        IngestResult::Applied { births: 1, .. }
    ));
    // The root moved with that ingest, so the witness below needs it cached too.
    let cq = pic
        .query_call(index, anon(), "get_certificate", Encode!().unwrap())
        .expect("get_certificate");
    let low_cert = Decode!(&cq, Option<Vec<u8>>, Vec<u8>)
        .unwrap()
        .0
        .expect("certificate present");
    let pr = relay(
        &pic,
        proxy,
        tasks,
        "push_root",
        Encode!(&low_cert).unwrap(),
        1_000_000_000u128,
    );
    assert!(matches!(
        Decode!(&pr, TaskResult).unwrap(),
        TaskResult::RootPushed
    ));
    let bq = pic
        .query_call(
            index,
            anon(),
            "get_birth",
            Encode!(&low_escrow.to_vec()).unwrap(),
        )
        .expect("get_birth");
    let low_witness = Decode!(&bq, Option<BirthView>, Vec<u8>).unwrap().1;

    let low_msg = protocol::register_message(
        "devnet",
        &tasks.to_text(),
        &low_bs58,
        &hex::encode(text_hash),
        duration,
    );
    let low_text = signed_request(
        &donor,
        &low_msg,
        &[
            ("recipient", bs58::encode(recipient).into_string()),
            ("gross", low_gross.to_string()),
            ("deadline", deadline.to_string()),
            ("nonce", low_nonce.to_string()),
            ("witness", hex::encode(&low_witness)),
        ],
    );
    assert!(
        pic.update_call(tasks, anon(), "register_task", Encode!(&low_text).unwrap())
            .is_err(),
        "a sub-floor registration with a valid birth proof must die at the \
         boundary, not be executed and answered `GrossBelowFloor`"
    );
    // …and the same request one unit above the floor is a different story: the
    // boundary has no quarrel with it. (Proven by the successful register above,
    // which is exactly this request at `gross = 2_000_000`.)

    // Recipient declines → the task is Decided{Cancel}.
    let decline_msg = protocol::decline_message("devnet", &tasks.to_text(), &task_bs58);
    let decline_text = signed_request(&recipient_sk, &decline_msg, &[]);
    let dr = pic
        .update_call(tasks, anon(), "decline", Encode!(&decline_text).unwrap())
        .expect("decline admitted");
    assert!(
        matches!(Decode!(&dr, TaskResult).unwrap(), TaskResult::Advanced(_)),
        "decline advances to Decided"
    );

    // Paid request_signature → a real threshold Ed25519 `Signed{Cancel}` verdict.
    let inner = Encode!(&"devnet".to_string(), &task_bs58).unwrap();
    let arg = Encode!(
        &tasks,
        &"request_signature".to_string(),
        &inner,
        &26_200_000_000u128
    )
    .unwrap();
    let sr = pic
        .update_call(proxy, anon(), "relay", arg)
        .expect("relay request_signature");
    let sr_raw = Decode!(&sr, Vec<u8>).unwrap();
    let signed = Decode!(&sr_raw, TaskResult).unwrap();
    let signature = match signed {
        TaskResult::Signed { outcome, signature } => {
            assert_eq!(outcome, 1, "cancel outcome");
            assert_eq!(signature.len(), 64, "a 64-byte Ed25519 signature");
            signature
        }
        other => panic!("expected Signed{{Cancel}}, got {other:?}"),
    };

    // The signature is a valid Ed25519 signature over the verdict message
    // `VERDICT_DOMAIN ‖ program_id(32) ‖ outcome` for the escrow's resolver — exactly
    // what Solana's ed25519 program (and the two-outcome `claim`'s
    // `assert_resolver_signed`) checks. Verifying it here proves the on-chain claim
    // would accept it (the money movement itself is covered by
    // `two-outcome/tests/claim.rs`). This is the cross-chain link, D8.
    let mut verdict = b"crown:two-outcome:devnet".to_vec();
    verdict.extend_from_slice(&factory()); // program_id == crate::ID == config::FACTORY
    verdict.push(1u8); // cancel
    verdict.extend_from_slice(&FEE_BPS.to_le_bytes());
    verdict.extend_from_slice(&fee_wallet());
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&resolver)
        .expect("resolver is a valid Ed25519 public key");
    let sig = ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature");
    vk.verify_strict(&verdict, &sig)
        .expect("the threshold verdict signature verifies against the resolver");
}

/// Milestone 5: the branch the game exists for — work accepted and **paid**.
/// `accept` → `ready` → a reputation-weighted `vote` → the window closes → a real
/// threshold `Signed{Settle}`, verified against the task's resolver. With the
/// `Cancel` half above, both terminal outcomes are now produced on a replica, and
/// `accept`/`ready`/`vote` are executed as endpoints rather than as `state::`
/// calls — until this test none of the three had ever run inside a canister.
///
/// **Two tasks, and that is the point.** With the verdict default flipped in the
/// recipient's favour (`LOGIC_VERSION` 5: silence and a tie settle), a lone settle
/// case is vacuously green — it passes with the ballot uncounted, or with `choice`
/// never read, because doing nothing settles too. The second task is voted
/// `not_done` by the same voter with the same weight and must come out `Cancel`.
/// Only the pair can go red in its own case (`P7.13`).
///
/// The vote's weight is not asserted into existence either: it is real book
/// reputation, folded by the index from a `Settled` the splitter emitted, and the
/// witness is whatever `get_reputation` hands out.
#[test]
fn a_weighted_vote_decides_both_verdicts_and_signs_them() {
    let game_bytes = tasks_game_wasm();
    let (pic, index, mock, proxy) = setup();

    let root_key = pic.root_key().expect("nns root key");
    let app = pic.topology().get_app_subnets()[0];
    let tasks = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(tasks, 40_000_000_000_000);
    let init = Some(InitArgs {
        nns_root_key: root_key,
        index,
    });
    pic.install_canister(tasks, game_bytes, Encode!(&init).unwrap(), None);
    let b = pic
        .update_call(tasks, anon(), "bootstrap", Encode!().unwrap())
        .expect("bootstrap");
    assert!(matches!(
        Decode!(&b, TaskResult).unwrap(),
        TaskResult::KeyBootstrapped
    ));
    // `bootstrap` is admitted only while the master key is missing (spec §Граница).
    // The very same call that just succeeded is now dropped at the boundary — for
    // free, before any replicated execution — so a one-shot setup method cannot be
    // turned into an unbounded free `update` by replaying it.
    assert!(
        pic.update_call(tasks, anon(), "bootstrap", Encode!().unwrap())
            .is_err(),
        "a repeat bootstrap must be dropped once the key is taken"
    );

    let donor = SigningKey::from_bytes(&[9u8; 32]);
    let donor_pk = donor.verifying_key().to_bytes();
    let recipient_sk = SigningKey::from_bytes(&[5u8; 32]);
    let recipient = recipient_sk.verifying_key().to_bytes();
    // A third wallet: it holds reputation *at this recipient* and never touches an
    // escrow. Weight is local to the recipient (`00 §10.1`), so this is the only
    // thing that gives the ballot any weight at all.
    let voter_sk = SigningKey::from_bytes(&[3u8; 32]);
    let voter = voter_sk.verifying_key().to_bytes();

    let gross = 2_000_000u64;
    let duration = 100_000u64;
    // The escrow `deadline` is the game's only clock (§Тайминги): both `cutoff` and
    // `voting_end` are read off it. Set to the minimum the registration rule allows
    // plus an hour of slack, so the whole window is short enough to step over
    // inside one test — the cancel path above never has to reach `voting_end` and
    // uses a year-2096 deadline instead.
    let now_secs = (pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000) as i64;
    let deadline = now_secs + duration as i64 + VOTING_PERIOD as i64 + DEADLINE_MARGIN + 3_600;
    let voting_end = deadline - DEADLINE_MARGIN;

    // The two tasks differ **only** in `nonce` and in how the voter votes: same
    // donor, recipient, gross and deadline. So the verdicts can only diverge on
    // the ballot.
    let cases: [(u64, &str, u8, &str); 2] = [
        (1, "done", 0, "sig-settle-birth"),
        (2, "not_done", 1, "sig-cancel-birth"),
    ];

    // ---- derive both tasks and fold both births ----
    let mut derived = Vec::new();
    for (nonce, choice, outcome, birth_sig) in cases {
        let task_id = protocol::task_id(
            tasks.as_slice(),
            donor_pk,
            recipient,
            gross,
            deadline,
            FEE_BPS,
            fee_wallet(),
            nonce,
            duration,
            VOTING_PERIOD,
        );
        let task_bs58 = bs58::encode(task_id).into_string();

        let rq = pic
            .query_call(tasks, anon(), "get_resolver", Encode!(&task_bs58).unwrap())
            .expect("get_resolver");
        let resolver: [u8; 32] =
            bs58::decode(Decode!(&rq, Option<String>).unwrap().expect("resolver"))
                .into_vec()
                .unwrap()
                .try_into()
                .unwrap();

        let salt = crown_salt::two_outcome::two_outcome(
            donor_pk,
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
                    Pubkey::new_from_array(donor_pk),
                    Pubkey::new_from_array(escrow_arr),
                    salt,
                ),
                600 + nonce,
            ),
            birth_sig,
        );
        assert!(
            matches!(r, IngestResult::Applied { births: 1, .. }),
            "task {nonce}: the birth must fold: {r:?}"
        );

        derived.push((nonce, choice, outcome, task_bs58, resolver, escrow_arr));
    }

    // ---- the voter buys its weight: one real settlement, folded by the index ----
    // The only way into the book (`00 §9`, harness §1). Above the index's dust
    // floor ($0.20) and above `MIN_VOTE_WEIGHT`, or the ballot would not be
    // admitted at all.
    let weight_gross = 500_000u64;
    let r = ingest(
        &pic,
        mock,
        proxy,
        index,
        consistent_reply(
            settlement_tx(Pubkey::new_from_array(voter), recipient, weight_gross),
            700,
        ),
        "sig-voter-weight",
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

    let chain = conditional_tasks::field::chain_id("devnet");
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
        u128::from(weight_gross) >= MIN_VOTE_WEIGHT,
        "the seeded weight must clear the vote threshold, or nothing below is reachable"
    );
    assert!(
        !weight_witness.is_empty(),
        "a reputation witness is returned"
    );

    // ---- one paid root refresh covers every proof above ----
    let cq = pic
        .query_call(index, anon(), "get_certificate", Encode!().unwrap())
        .expect("get_certificate");
    let cert = Decode!(&cq, Option<Vec<u8>>, Vec<u8>)
        .unwrap()
        .0
        .expect("certificate present");
    let before_root = pic.cycle_balance(tasks);
    let pr = relay(
        &pic,
        proxy,
        tasks,
        "push_root",
        Encode!(&cert).unwrap(),
        1_000_000_000u128,
    );
    assert!(
        matches!(Decode!(&pr, TaskResult).unwrap(), TaskResult::RootPushed),
        "the index certificate authenticates a root"
    );
    assert_price_covers_the_work(
        "push_root",
        before_root,
        pic.cycle_balance(tasks),
        1_000_000_000,
    );

    // ---- register → accept → ready → vote, both tasks, direct ingress ----
    let text_hash = [0xabu8; 32];
    for (nonce, choice, _outcome, task_bs58, _resolver, escrow_arr) in &derived {
        let bq = pic
            .query_call(
                index,
                anon(),
                "get_birth",
                Encode!(&escrow_arr.to_vec()).unwrap(),
            )
            .expect("get_birth");
        let witness = Decode!(&bq, Option<BirthView>, Vec<u8>).unwrap().1;

        let msg = protocol::register_message(
            "devnet",
            &tasks.to_text(),
            task_bs58,
            &hex::encode(text_hash),
            duration,
        );
        let extras = vec![
            ("recipient", bs58::encode(recipient).into_string()),
            ("gross", gross.to_string()),
            ("deadline", deadline.to_string()),
            ("nonce", nonce.to_string()),
            ("witness", hex::encode(&witness)),
        ];
        let rr = pic
            .update_call(
                tasks,
                anon(),
                "register_task",
                Encode!(&signed_request(&donor, &msg, &extras)).unwrap(),
            )
            .expect("register must be admitted");
        assert!(
            matches!(Decode!(&rr, TaskResult).unwrap(), TaskResult::Materialized),
            "task {nonce}: register must materialize"
        );

        // The recipient takes the task (the text becomes public) and declares it
        // done. Both are wallet-signed ingress the boundary admits by state.
        let accept_text = signed_request(
            &recipient_sk,
            &protocol::accept_message("devnet", &tasks.to_text(), task_bs58),
            &[],
        );

        // Size is cut **first**, before anything is parsed (`MAX_ARG_BYTES` = 8 KiB).
        // Padded with an unsigned extra the parser would otherwise ignore, so this
        // request is valid in every other respect — the *only* reason it dies is its
        // length, and the unpadded twin below proves it by being admitted.
        let padded = format!("{accept_text}\npadding: {}", "x".repeat(9_000));
        assert!(
            padded.len() > 8 * 1024,
            "the padded request has to actually exceed the cap"
        );
        assert!(
            pic.update_call(tasks, anon(), "accept", Encode!(&padded).unwrap())
                .is_err(),
            "task {nonce}: an oversized ingress must be dropped before it is parsed"
        );

        let ar = pic
            .update_call(tasks, anon(), "accept", Encode!(&accept_text).unwrap())
            .expect("accept admitted");
        assert!(
            matches!(
                Decode!(&ar, TaskResult).unwrap(),
                TaskResult::Advanced(TaskStateView::Accepted)
            ),
            "task {nonce}: accept must reveal the text"
        );

        // Byte-identical replay of a now-doomed action. The signed half carries no
        // nonce, so one observed valid message is a flood template; the boundary
        // refuses it by **state**, not just by signer, and the canister is never
        // billed for the round (`cost.md §6` #2).
        assert!(
            pic.update_call(tasks, anon(), "accept", Encode!(&accept_text).unwrap())
                .is_err(),
            "task {nonce}: a second accept is doomed and must die at the boundary"
        );
        let rdy = pic
            .update_call(
                tasks,
                anon(),
                "ready",
                Encode!(&signed_request(
                    &recipient_sk,
                    &protocol::ready_message("devnet", &tasks.to_text(), task_bs58),
                    &[]
                ))
                .unwrap(),
            )
            .expect("ready admitted");
        assert!(
            matches!(
                Decode!(&rdy, TaskResult).unwrap(),
                TaskResult::Advanced(TaskStateView::Voting)
            ),
            "task {nonce}: ready must open the voting window"
        );

        // The ballot. Its weight is proven, not asserted: a hash-tree walk over
        // the reputation witness against the root pushed above — the same path
        // `inspect_message` ran to admit this very call.
        let vr = pic
            .update_call(
                tasks,
                anon(),
                "vote",
                Encode!(&signed_request(
                    &voter_sk,
                    &protocol::vote_message("devnet", &tasks.to_text(), task_bs58, choice),
                    &[("weight_witness", hex::encode(&weight_witness))]
                ))
                .unwrap(),
            )
            .unwrap_or_else(|e| {
                panic!("task {nonce}: a weight-proven vote must be admitted: {e:?}")
            });
        assert!(
            matches!(
                Decode!(&vr, TaskResult).unwrap(),
                TaskResult::Advanced(TaskStateView::Voting)
            ),
            "task {nonce}: the vote is recorded and the window stays open"
        );
    }

    // Still undecided while the window is open — no verdict to sign yet.
    for (nonce, _, _, task_bs58, _, _) in &derived {
        let v = pic
            .query_call(tasks, anon(), "get_verdict", Encode!(task_bs58).unwrap())
            .expect("get_verdict");
        assert!(
            Decode!(&v, Option<TaskStateView>).unwrap().is_none(),
            "task {nonce}: no verdict before the window closes"
        );
    }

    // ---- the window closes on its own: no timer, a pure function of `deadline` ----
    pic.advance_time(std::time::Duration::from_secs(
        (voting_end - now_secs + 1) as u64,
    ));
    pic.tick();

    for (nonce, choice, outcome, task_bs58, resolver, _) in &derived {
        let v = pic
            .query_call(tasks, anon(), "get_verdict", Encode!(task_bs58).unwrap())
            .expect("get_verdict");
        let got = Decode!(&v, Option<TaskStateView>)
            .unwrap()
            .expect("the tally is lazy but total — reading past the window decides");
        let decided_as_expected = matches!(
            (*outcome, got),
            (0, TaskStateView::DecidedSettle) | (1, TaskStateView::DecidedCancel)
        );
        assert!(
            decided_as_expected,
            "task {nonce}: a single `{choice}` vote must decide outcome {outcome}, got {got:?}"
        );

        // Paid pull → a real threshold Ed25519 signature over this task's verdict.
        let before_sign = pic.cycle_balance(tasks);
        let sr = relay(
            &pic,
            proxy,
            tasks,
            "request_signature",
            Encode!(&"devnet".to_string(), task_bs58).unwrap(),
            26_200_000_000u128,
        );
        let signature = match Decode!(&sr, TaskResult).unwrap() {
            TaskResult::Signed {
                outcome: got_outcome,
                signature,
            } => {
                assert_eq!(got_outcome, *outcome, "task {nonce}: signed outcome");
                assert_eq!(signature.len(), 64, "a 64-byte Ed25519 signature");
                assert_price_covers_the_work(
                    "request_signature",
                    before_sign,
                    pic.cycle_balance(tasks),
                    26_200_000_000,
                );
                signature
            }
            other => panic!("task {nonce}: expected Signed, got {other:?}"),
        };

        // What Solana's ed25519 program (and `two-outcome`'s `assert_resolver_signed`)
        // checks: the verdict message under this task's resolver. Verifying it here
        // proves `claim(settle)` on chain would accept these bytes.
        let mut verdict = b"crown:two-outcome:devnet".to_vec();
        verdict.extend_from_slice(&factory());
        verdict.push(*outcome);
        verdict.extend_from_slice(&FEE_BPS.to_le_bytes());
        verdict.extend_from_slice(&fee_wallet());
        let vk = ed25519_dalek::VerifyingKey::from_bytes(resolver)
            .expect("resolver is a valid Ed25519 public key");
        let sig = ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature");
        vk.verify_strict(&verdict, &sig)
            .unwrap_or_else(|e| panic!("task {nonce}: the verdict signature must verify: {e:?}"));
    }
}
