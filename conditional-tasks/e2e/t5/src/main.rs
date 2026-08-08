//! conditional-tasks T5 — live devnet e2e.
//!
//! The one loop the repo could not close before: a **real** escrow on Solana
//! devnet, proven to a **local** index, decided by the game, signed by a **real**
//! threshold key, and claimed back on devnet with that signature. Money moves on
//! both ends; nothing about the verdict is simulated.
//!
//!   1. PocketIC: index + mock SOL RPC + relay proxy + tasks (`key_1`);
//!   2. derive `task_id` → `get_resolver` → escrow address;
//!   3. **devnet**: `create_escrow` funds the vault with real test-USDC;
//!   4. the real transaction is fetched and folded by the index into a birth;
//!   5. `push_root` → `register_task` (direct ingress) → `decline`;
//!   6. paid `request_signature` → a real 64-byte Ed25519 threshold signature;
//!   7. **devnet**: `claim(cancel)` with that signature → the vault returns to the
//!      donor and closes.
//!
//! Why PocketIC directly rather than a local dfx replica: none — dfx 0.32's local
//! network *is* PocketIC (`pocket-ic-pid` in its network dir; `dfx start
//! --pocketic` is a no-op for that reason), and it signs threshold Ed25519 fine
//! under `key_1`. Driving the harness in-process just keeps the whole run in one
//! program; `dfx deploy` + `dfx canister call` reproduces it step by step. The key
//! name is an environment fact, not a capability one — `key_1` locally and on IC
//! mainnet, `test_key_1` on a test subnet — and `config/testnet.toml` now names
//! it, so there is one devnet profile rather than two.
//!
//! The one simulated link is the *transport* of the transaction into the index:
//! the SOL RPC canister lives on IC mainnet and cannot be reached from a local
//! replica, so its reply is served by the mock. The transaction bytes inside that
//! reply are the real ones fetched from devnet, and the index parses, recognizes
//! and folds them exactly as it would in production. What this run does **not**
//! cover is the multi-provider RPC consensus path.
//!
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic \
//!     cargo run --manifest-path crown-games/conditional-tasks/e2e/t5/Cargo.toml

use anchor_lang::{InstructionData, ToAccountMetas};
use candid::{CandidType, Decode, Deserialize, Encode, Principal, Reserved};
use conditional_tasks::{protocol, InitArgs, TaskResult};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use pocket_ic::PocketIcBuilder;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    ed25519_program,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_transaction_status::{EncodedTransaction as UiTx, UiTransactionEncoding};
use spl_associated_token_account::get_associated_token_address;
use std::error::Error;

type R<T> = Result<T, Box<dyn Error>>;

const URL: &str = "https://api.devnet.solana.com";
/// 2 USDC — above the game floor (`min_gross` = 1.86) and the index dust floor.
const GROSS: u64 = 2_000_000;
const DURATION: u64 = 100_000;
// `VOTING_PERIOD`/`FEE_BPS` are mirrored from `config/testnet.toml`, and every one
// of them enters `task_id`. A mirror goes stale silently: the canister recomputes
// the id from its own baked config, refuses the mismatch, and the boundary reports
// nothing but "rejected" — the failure this driver already cost four runs to find.
// `auction/e2e/a5` solves it properly by reading the profile at runtime (`Config`);
// port that here rather than trusting these two lines to stay in sync.
const VOTING_PERIOD: u64 = 120;
const FEE_BPS: u16 = 300;
const INGEST_PRICE: u128 = 17_000_000_000;
const ROOT_PRICE: u128 = 1_000_000_000;
const SIGN_PRICE: u128 = 26_200_000_000;
const CANCEL: u8 = 1;
const SEP: &str = "\n---\n";

const INDEX_WASM: &str =
    "../../../../crown-indexer/target/wasm32-unknown-unknown/release/crown_indexer.wasm";
const MOCK_WASM: &str = "../../../e2e-fixtures/mock-sol-rpc/target/wasm32-unknown-unknown/release/mock_sol_rpc.wasm";
const PROXY_WASM: &str = "../../../e2e-fixtures/relay-proxy/target/wasm32-unknown-unknown/release/relay_proxy.wasm";
const TASKS_WASM: &str = "../../target/e2e/wasm32-unknown-unknown/release/conditional_tasks.wasm";

/// The index's pinned SOL RPC principal (`tghme-zyaaa-aaaar-qarca-cai`).
const SOL_RPC: [u8; 10] = [0, 0, 0, 0, 2, 48, 4, 68, 1, 1];

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

/// Mirrors `crown-indexer.did` exactly (copied, not imported: two canister
/// crates in one binary collide on `canister_init`).
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
    AfterCutover,
    /// The settlement's payer is an escrow whose birth the index has not folded
    /// yet — nothing is folded and the signature stays free. Fold the escrow's
    /// `create_escrow` transaction first, then submit this one again
    /// (`crown-indexer/src/state.rs::attributable`).
    UnknownBirth,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct BirthView {
    slot: u64,
    donor: Vec<u8>,
}

fn anon() -> Principal {
    Principal::anonymous()
}

fn build(dir: &str, extra: &[&str], target_dir: Option<&str>) {
    let mut args = vec!["build", "--release", "--target", "wasm32-unknown-unknown"];
    args.extend_from_slice(extra);
    if let Some(t) = target_dir {
        args.push("--target-dir");
        args.push(t);
    }
    let status = std::process::Command::new("cargo")
        .args(&args)
        .current_dir(dir)
        .status()
        .expect("cargo build");
    assert!(status.success(), "build failed in {dir}");
}

/// `force` is for the profile-baked game wasm: its bytes depend on `config/`,
/// and a cached artifact from an earlier config silently disagrees with the ids
/// this driver derives (a stale `fee_wallet` alone is a `TaskIdMismatch` the
/// boundary refuses, with nothing to read but "rejected").
fn wasm(path: &str, dir: &str, extra: &[&str], td: Option<&str>, force: bool) -> Vec<u8> {
    if force || !std::path::Path::new(path).exists() {
        build(dir, extra, td);
    }
    std::fs::read(path).unwrap_or_else(|_| panic!("read wasm {path}"))
}

/// `<message>\n---\npubkey: ..\nsignature: ..\n<extras>` — the tasks wire format.
fn signed_request(sk: &SigningKey, message: &str, extras: &[(&str, String)]) -> String {
    let pk = bs58::encode(sk.verifying_key().to_bytes()).into_string();
    let sig = bs58::encode(sk.sign(message.as_bytes()).to_bytes()).into_string();
    let mut s = format!("{message}{SEP}pubkey: {pk}\nsignature: {sig}");
    for (k, v) in extras {
        s.push_str(&format!("\n{k}: {v}"));
    }
    s
}

/// An ed25519-program instruction carrying a signature produced elsewhere (here:
/// by the canister's threshold key). Layout mirrors `crown_escrow::parse_ed25519_signed`.
fn ed25519_ix(pubkey: &[u8; 32], signature: &[u8], message: &[u8]) -> Instruction {
    let pk_off: u16 = 16;
    let sig_off: u16 = pk_off + 32;
    let msg_off: u16 = sig_off + 64;
    let mut d = Vec::new();
    d.push(1u8); // one signature
    d.push(0u8); // padding
    d.extend_from_slice(&sig_off.to_le_bytes());
    d.extend_from_slice(&u16::MAX.to_le_bytes());
    d.extend_from_slice(&pk_off.to_le_bytes());
    d.extend_from_slice(&u16::MAX.to_le_bytes());
    d.extend_from_slice(&msg_off.to_le_bytes());
    d.extend_from_slice(&(message.len() as u16).to_le_bytes());
    d.extend_from_slice(&u16::MAX.to_le_bytes());
    d.extend_from_slice(pubkey);
    d.extend_from_slice(signature);
    d.extend_from_slice(message);
    Instruction {
        program_id: ed25519_program::ID,
        accounts: vec![],
        data: d,
    }
}

fn send(client: &RpcClient, payer: &Keypair, ixs: &[Instruction]) -> R<String> {
    let bh = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), &[payer], bh);
    Ok(client.send_and_confirm_transaction(&tx)?.to_string())
}

fn balance(client: &RpcClient, ata: &Pubkey) -> u64 {
    client
        .get_token_account_balance(ata)
        .ok()
        .and_then(|b| b.amount.parse().ok())
        .unwrap_or(0)
}

fn closed(client: &RpcClient, addr: &Pubkey) -> bool {
    client
        .get_account_with_commitment(addr, CommitmentConfig::confirmed())
        .map(|r| r.value.is_none())
        .unwrap_or(false)
}

fn main() -> R<()> {
    let client = RpcClient::new_with_commitment(URL.to_string(), CommitmentConfig::confirmed());
    let home = std::env::var("HOME")?;

    // The donor is the real funded devnet wallet; its ed25519 secret also signs
    // the register request, so the on-chain payer and the wallet the canister
    // authenticates are one key.
    let donor_kp = solana_sdk::signature::read_keypair_file(format!(
        "{home}/.config/solana/crown-index-e2e-donor.json"
    ))
    .map_err(|e| format!("read donor keypair: {e}"))?;
    let donor_sk = SigningKey::from_bytes(&donor_kp.to_bytes()[..32].try_into()?);
    let donor_pk = donor_kp.pubkey().to_bytes();
    let donor_ata = get_associated_token_address(&donor_kp.pubkey(), &two_outcome::USDC_MINT);
    println!(
        "donor {} — {} USDC",
        donor_kp.pubkey(),
        balance(&client, &donor_ata)
    );

    let fee_wallet_kp = solana_sdk::signature::read_keypair_file(format!(
        "{home}/.config/solana/crown-fee-wallet.json"
    ))
    .map_err(|e| format!("read fee wallet: {e}"))?;
    let fee_wallet = fee_wallet_kp.pubkey().to_bytes();

    // The recipient is a fresh keypair — it must sign its own `decline`.
    let recipient_kp = Keypair::new();
    let recipient_sk = SigningKey::from_bytes(&recipient_kp.to_bytes()[..32].try_into()?);
    let recipient = recipient_kp.pubkey().to_bytes();

    // ---- 1) PocketIC: index + mock SOL RPC + relay proxy + tasks(key_1) ----
    println!("\n[1] local IC: index + mock SOL RPC + relay proxy + tasks(key_1)");
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
        wasm(
            INDEX_WASM,
            "../../../../crown-indexer",
            &["--lib"],
            None,
            false,
        ),
        Encode!().unwrap(),
        None,
    );

    let mock = pic
        .create_canister_with_id(None, None, Principal::from_slice(&SOL_RPC))
        .expect("create mock at the SOL_RPC principal");
    pic.add_cycles(mock, 5_000_000_000_000);
    pic.install_canister(
        mock,
        wasm(MOCK_WASM, "../../../e2e-fixtures/mock-sol-rpc", &[], None, false),
        Encode!().unwrap(),
        None,
    );

    let proxy = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(proxy, 100_000_000_000_000);
    pic.install_canister(
        proxy,
        wasm(PROXY_WASM, "../../../e2e-fixtures/relay-proxy", &[], None, false),
        Encode!().unwrap(),
        None,
    );

    let tasks = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(tasks, 20_000_000_000_000);
    let init = Some(InitArgs {
        nns_root_key: pic.root_key().expect("nns root key"),
        index,
    });
    pic.install_canister(
        tasks,
        wasm(
            TASKS_WASM,
            "../../canister",
            &["-p", "conditional-tasks"],
            Some("../target/e2e"), // relative to the canister dir — must match TASKS_WASM
            true,
        ),
        Encode!(&init).unwrap(),
        None,
    );

    let b = pic
        .update_call(tasks, anon(), "bootstrap", Encode!().unwrap())
        .map_err(|e| format!("{e:?}"))?;
    assert!(matches!(
        Decode!(&b, TaskResult)?,
        TaskResult::KeyBootstrapped
    ));
    println!("    ✓ threshold key bootstrapped (key_1)");

    // ---- 2) task id → resolver → escrow address ----
    // The escrow deadline must outlive the whole task window on both clocks: the
    // canister checks `deadline ≥ now + duration + voting_period + margin`, and
    // `create_escrow` refuses a deadline already in the past on devnet.
    // Fixed, not per-run: the escrow is the expensive half, so re-runs re-derive
    // the same address and reuse the one already on chain (created below only if
    // it is absent). Year 2030 — comfortably past every clock in play.
    let deadline: i64 = 1_900_000_000;
    let nonce: u64 = 1;
    let task_id = protocol::task_id(
        tasks.as_slice(),
        donor_pk,
        recipient,
        GROSS,
        deadline,
        FEE_BPS,
        fee_wallet,
        nonce,
        DURATION,
        VOTING_PERIOD,
    );
    let task_bs58 = bs58::encode(task_id).into_string();
    let rq = pic
        .query_call(tasks, anon(), "get_resolver", Encode!(&task_bs58).unwrap())
        .map_err(|e| format!("{e:?}"))?;
    let resolver: [u8; 32] = bs58::decode(Decode!(&rq, Option<String>)?.expect("resolver"))
        .into_vec()?
        .try_into()
        .map_err(|_| "resolver is not 32 bytes")?;
    let salt = crown_salt::two_outcome::two_outcome(
        donor_pk, recipient, GROSS, deadline, resolver, FEE_BPS, fee_wallet, nonce,
    );
    let (escrow_arr, _) =
        crown_derive::solana_pda_address(two_outcome::ID.to_bytes(), &[b"escrow", &salt])
            .ok_or("derive escrow address")?;
    let escrow = Pubkey::new_from_array(escrow_arr);
    let vault = get_associated_token_address(&escrow, &two_outcome::USDC_MINT);
    println!("\n[2] task {task_bs58}\n    escrow {escrow}");

    // ---- 3) devnet: create the escrow for real ----
    println!("\n[3] devnet: create_escrow");
    let create_ix = Instruction {
        program_id: two_outcome::ID,
        accounts: two_outcome::accounts::CreateEscrow {
            donor: donor_kp.pubkey(),
            escrow,
            vault,
            donor_ata,
            mint: two_outcome::USDC_MINT,
            token_program: spl_token::ID,
            associated_token_program: spl_associated_token_account::ID,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
        data: two_outcome::instruction::CreateEscrow {
            salt,
            recipient: Pubkey::new_from_array(recipient),
            gross: GROSS,
            deadline,
            resolver: Pubkey::new_from_array(resolver),
            fee_bps: FEE_BPS,
            fee_wallet: Pubkey::new_from_array(fee_wallet),
            nonce,
        }
        .data(),
    };
    let create_sig = if closed(&client, &escrow) {
        let sig = send(&client, &donor_kp, &[create_ix])?;
        println!("    create_escrow tx {sig}");
        sig
    } else {
        let sig = client
            .get_signatures_for_address(&escrow)?
            .last()
            .ok_or("escrow exists but has no transaction history")?
            .signature
            .clone();
        println!("    escrow already on chain, reusing tx {sig}");
        sig
    };
    let funded = balance(&client, &vault);
    assert_eq!(funded, GROSS, "vault must hold the gross");
    println!("    ✓ vault funded: {funded}");

    // ---- 4) the real transaction is folded by the index into a birth ----
    println!("\n[4] index: fold the real devnet transaction into a birth");
    // The index only ever reads `finalized` (`00 §6`), so the run waits for
    // finality rather than lowering the bar to `confirmed`: a reorg before
    // finality means the event never happened, and folding a merely-confirmed
    // transaction would prove nothing about the production path.
    let cfg = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Base58),
        commitment: Some(CommitmentConfig::finalized()),
        max_supported_transaction_version: Some(0),
    };
    let sig_parsed = create_sig.parse()?;
    println!("    waiting for finality…");
    let fetched = loop {
        match client.get_transaction_with_config(&sig_parsed, cfg) {
            Ok(t) => break t,
            Err(_) => std::thread::sleep(std::time::Duration::from_secs(3)),
        }
    };
    let tx_b58 = match fetched.transaction.transaction {
        UiTx::Binary(s, _) => s,
        _ => return Err("expected a base58-encoded transaction".into()),
    };
    let reply =
        MultiGetTransactionResult::Consistent(GetTransactionResult::Ok(Some(TransactionReply {
            slot: fetched.slot,
            transaction: EncodedTxWithMeta {
                meta: Some(TxMeta {
                    status: TxStatus::Ok,
                    innerInstructions: None,
                    loadedAddresses: None,
                }),
                transaction: EncodedTransaction::binary(tx_b58, Encoding::base58),
            },
        })));
    pic.update_call(mock, anon(), "set_reply", Encode!(&Encode!(&reply).unwrap()).unwrap())
        .map_err(|e| format!("{e:?}"))?;
    let inner = Encode!(&create_sig).unwrap();
    let arg = Encode!(&index, &"ingest".to_string(), &inner, &INGEST_PRICE).unwrap();
    let ir = pic
        .update_call(proxy, anon(), "relay", arg)
        .map_err(|e| format!("{e:?}"))?;
    let ingested = Decode!(&Decode!(&ir, Vec<u8>)?, IngestResult)?;
    match ingested {
        IngestResult::Applied { births: 1, .. } => {}
        other => return Err(format!("expected one birth, got {other:?}").into()),
    }
    println!("    ✓ birth recognized from the real transaction");

    // ---- 5) certificate → push_root → register → decline ----
    println!("\n[5] proof + register + decline");
    let cq = pic
        .query_call(index, anon(), "get_certificate", Encode!().unwrap())
        .map_err(|e| format!("{e:?}"))?;
    let cert = Decode!(&cq, Option<Vec<u8>>, Vec<u8>)?
        .0
        .expect("certificate");
    let bq = pic
        .query_call(
            index,
            anon(),
            "get_birth",
            Encode!(&escrow.to_bytes().to_vec()).unwrap(),
        )
        .map_err(|e| format!("{e:?}"))?;
    let witness = Decode!(&bq, Option<BirthView>, Vec<u8>)?.1;

    let root_arg = Encode!(
        &tasks,
        &"push_root".to_string(),
        &Encode!(&cert).unwrap(),
        &ROOT_PRICE
    )
    .unwrap();
    let pr = pic
        .update_call(proxy, anon(), "relay", root_arg)
        .map_err(|e| format!("{e:?}"))?;
    assert!(matches!(
        Decode!(&Decode!(&pr, Vec<u8>)?, TaskResult)?,
        TaskResult::RootPushed
    ));

    let text_hash = [0xabu8; 32];
    let msg = protocol::register_message(
        "devnet",
        &tasks.to_text(),
        &task_bs58,
        &hex::encode(text_hash),
        DURATION,
    );
    let extras = vec![
        ("recipient", bs58::encode(recipient).into_string()),
        ("gross", GROSS.to_string()),
        ("deadline", deadline.to_string()),
        ("nonce", nonce.to_string()),
        ("witness", hex::encode(&witness)),
    ];
    let register_text = signed_request(&donor_sk, &msg, &extras);
    let rr = match pic.update_call(
        tasks,
        anon(),
        "register_task",
        Encode!(&register_text).unwrap(),
    ) {
        Ok(bytes) => bytes,
        Err(boundary) => {
            // `inspect_message` refuses without a reason by design. The same
            // `admit_register` runs inside the update, and an inter-canister call
            // is not inspected — so route it through the proxy purely to read the
            // typed refusal instead of guessing.
            let arg = Encode!(
                &tasks,
                &"register_task".to_string(),
                &Encode!(&register_text).unwrap(),
                &0u128
            )
            .unwrap();
            let via = pic
                .update_call(proxy, anon(), "relay", arg)
                .map_err(|e| format!("{e:?}"))?;
            let reason = Decode!(&Decode!(&via, Vec<u8>)?, TaskResult)?;
            return Err(format!(
                "boundary refused register ({boundary:?}); the update says: {reason:?}"
            )
            .into());
        }
    };
    match Decode!(&rr, TaskResult)? {
        TaskResult::Materialized => println!("    ✓ registered against the real birth"),
        other => return Err(format!("register: {other:?}").into()),
    }

    let decline_msg = protocol::decline_message("devnet", &tasks.to_text(), &task_bs58);
    let dr = pic
        .update_call(
            tasks,
            anon(),
            "decline",
            Encode!(&signed_request(&recipient_sk, &decline_msg, &[])).unwrap(),
        )
        .map_err(|e| format!("{e:?}"))?;
    assert!(matches!(Decode!(&dr, TaskResult)?, TaskResult::Advanced(_)));
    println!("    ✓ recipient declined → Decided{{Cancel}}");

    // ---- 6) paid pull → a real threshold signature ----
    println!("\n[6] request_signature → real Ed25519 threshold verdict");
    let inner = Encode!(&"devnet".to_string(), &task_bs58).unwrap();
    let arg = Encode!(
        &tasks,
        &"request_signature".to_string(),
        &inner,
        &SIGN_PRICE
    )
    .unwrap();
    let sr = pic
        .update_call(proxy, anon(), "relay", arg)
        .map_err(|e| format!("{e:?}"))?;
    let signature = match Decode!(&Decode!(&sr, Vec<u8>)?, TaskResult)? {
        TaskResult::Signed { outcome, signature } => {
            assert_eq!(outcome, CANCEL, "declined task must resolve to cancel");
            assert_eq!(signature.len(), 64, "a 64-byte Ed25519 signature");
            println!("    ✓ signed: {}", hex::encode(&signature));
            signature
        }
        other => return Err(format!("request_signature: {other:?}").into()),
    };

    // ---- 7) devnet: claim with that signature ----
    println!("\n[7] devnet: claim(cancel) with the canister's signature");
    let before = balance(&client, &donor_ata);
    let recipient_ata =
        get_associated_token_address(&recipient_kp.pubkey(), &two_outcome::USDC_MINT);
    let fee_ata = get_associated_token_address(&fee_wallet_kp.pubkey(), &two_outcome::USDC_MINT);
    // `claim` needs both payout ATAs to exist even on cancel (the accounts are
    // resolved before the outcome is known).
    send(
        &client,
        &donor_kp,
        &[
            spl_associated_token_account::instruction::create_associated_token_account_idempotent(
                &donor_kp.pubkey(),
                &recipient_kp.pubkey(),
                &two_outcome::USDC_MINT,
                &spl_token::ID,
            ),
            spl_associated_token_account::instruction::create_associated_token_account_idempotent(
                &donor_kp.pubkey(),
                &fee_wallet_kp.pubkey(),
                &two_outcome::USDC_MINT,
                &spl_token::ID,
            ),
        ],
    )?;

    // The escrow's own fee fields close the message: a verdict signed for this
    // scope opens only escrows born with this game's price list (harness §9).
    let mut verdict = b"crown:two-outcome:devnet".to_vec();
    verdict.extend_from_slice(&two_outcome::ID.to_bytes());
    verdict.push(CANCEL);
    verdict.extend_from_slice(&FEE_BPS.to_le_bytes());
    verdict.extend_from_slice(&fee_wallet);
    let claim_ix = Instruction {
        program_id: two_outcome::ID,
        accounts: two_outcome::accounts::Claim {
            caller: donor_kp.pubkey(),
            escrow,
            vault,
            recipient_ata,
            fee_wallet_ata: fee_ata,
            donor: donor_kp.pubkey(),
            donor_ata,
            mint: two_outcome::USDC_MINT,
            token_program: spl_token::ID,
            splitter_program: two_outcome::SPLITTER,
            splitter_event_authority: Pubkey::find_program_address(
                &[b"__event_authority"],
                &two_outcome::SPLITTER,
            )
            .0,
            instructions: solana_sdk::sysvar::instructions::ID,
        }
        .to_account_metas(None),
        data: two_outcome::instruction::Claim { outcome: CANCEL }.data(),
    };
    let claim_sig = send(
        &client,
        &donor_kp,
        &[ed25519_ix(&resolver, &signature, &verdict), claim_ix],
    )?;
    println!("    claim tx {claim_sig}");

    let after = balance(&client, &donor_ata);
    assert_eq!(
        after,
        before + GROSS,
        "cancel returns the whole gross to the donor"
    );
    assert!(closed(&client, &vault), "vault must be closed after claim");
    println!("    ✓ donor refunded in full: {after}");
    println!("    ✓ vault closed");

    println!("\nT5 PASSED — real escrow, real threshold verdict, real claim on devnet.");
    Ok(())
}
