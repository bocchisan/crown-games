//! Full canister-game e2e — Part A (PocketIC): the birth-proof / signing path that
//! needs a real index + threshold key, without a live Solana RPC outcall.
//!
//! Milestone 1 (this file, for now): a mock SOL RPC canister at the index's pinned
//! `SOL_RPC` principal returns a synthetic `create_escrow` transaction, so a paid
//! `ingest` (fronted by the relay proxy with cycles) folds it into a **birth** —
//! proving the index's recognition path end-to-end on a replica. Later milestones
//! extend this to `register_task` → `request_signature` → a real `Signed` verdict.
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

fn fee_wallet() -> [u8; 32] {
    bs58::decode(FEE_WALLET_B58)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap()
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
    bs58::decode(TWO_OUTCOME_FACTORY)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap()
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
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&resolver)
        .expect("resolver is a valid Ed25519 public key");
    let sig = ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature");
    vk.verify_strict(&verdict, &sig)
        .expect("the threshold verdict signature verifies against the resolver");
}
