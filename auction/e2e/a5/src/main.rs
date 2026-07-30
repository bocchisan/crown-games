//! auction A5 — live devnet e2e.
//!
//! The loop the auction could not close before: **two real escrows** on Solana
//! devnet competing in one auction, proven to a **local** index, judged by a vote
//! whose weight is **real book reputation**, decided by the game, signed by a
//! **real** threshold key, and claimed back on devnet — settle for the winner,
//! cancel for the loser. Money moves on both ends; nothing about the verdict, the
//! vote weight or the escrow set is simulated.
//!
//!   1. PocketIC: index + mock SOL RPC + relay proxy + auction (`key_1`);
//!   2. **devnet**: a real `splitter.donate` buys the voter its reputation — the
//!      only way the system allows (`00 §9`), folded from chain by the index;
//!   3. derive `auction_id` → two lots → per-entry resolvers → escrow addresses;
//!   4. **devnet**: two `create_escrow` fund two vaults with real test-USDC;
//!   5. both real transactions are fetched and folded by the index into births;
//!   6. `push_root` → two `register_entry` (direct ingress) → materialize + top-up;
//!   7. `accept_lot` both → `pick_winner` → `ready` → **vote** with the book weight;
//!   8. the voting window closes → paid `request_signature` per entry: the winner
//!      resolves to settle, the loser to cancel — two real Ed25519 threshold
//!      signatures under two **different** leaf resolvers;
//!   9. **devnet**: `claim(settle)` pays the recipient net + the fee wallet, and
//!      `claim(cancel)` returns the loser's gross to its donor; both vaults close;
//!  10. the settlement is folded back: reputation lands on the **donor**, not on
//!      the escrow address — the whole loop, closed.
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
//! The one simulated link is the *transport* of a transaction into the index: the
//! SOL RPC canister lives on IC mainnet and cannot be reached from a local
//! replica, so its reply is served by the mock. The transaction bytes inside that
//! reply — including `meta.innerInstructions`, where a settlement's event and its
//! matching transfer actually live — are the real ones fetched from devnet, and
//! the index parses, recognizes and folds them exactly as it would in production.
//! What this run does **not** cover is the multi-provider RPC consensus path.
//!
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic \
//!     cargo run --manifest-path crown-games/auction/e2e/a5/Cargo.toml

use anchor_lang::{InstructionData, ToAccountMetas};
use auction::{protocol, AuctionResult, AuctionStateView, InitArgs};
use candid::{CandidType, Decode, Deserialize, Encode, Nat, Principal, Reserved};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use pocket_ic::{PocketIc, PocketIcBuilder, Time};
use sha2::{Digest, Sha256};
use solana_client::{rpc_client::RpcClient, rpc_config::RpcTransactionConfig};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    ed25519_program,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedTransaction as UiTx, UiInstruction,
    UiTransactionEncoding,
};
use spl_associated_token_account::get_associated_token_address;
use std::{error::Error, time::SystemTime};

type R<T> = Result<T, Box<dyn Error>>;

const URL: &str = "https://api.devnet.solana.com";
/// 2 USDC per entry — above the index dust floor and any game floor.
const GROSS: u64 = 250_000;
/// The reputation the voter buys itself: 0.5 USDC, comfortably over both
/// `MIN_VOTE_WEIGHT` (0.10) and the index's `MIN_GROSS` (0.20).
const SEED_GROSS: u64 = 250_000;
/// One hour of bidding — the run takes minutes, and a short window keeps the
/// escrow deadline rule (`+ perform + voting + 72h margin`) modest.
const DURATION: u64 = 3_600;
const SETTLE: u8 = 0;
const CANCEL: u8 = 1;
const SEP: &str = "\n---\n";
/// `crown-indexer/config/testnet.toml`. The index refuses anything below its own
/// price, and an `Underpaid` ingest folds nothing while looking like a no-op.
const INGEST_PRICE: u128 = 13_700_000_000;
/// The index's pinned SOL RPC principal (`tghme-zyaaa-aaaar-qarca-cai`).
const SOL_RPC: [u8; 10] = [0, 0, 0, 0, 2, 48, 4, 68, 1, 1];
/// How far the linear slot→time model may sit from the network before the anchor
/// is stale enough to matter. Devnet runs slightly faster than `slot_ms`, so the
/// model drifts *ahead* of real time — the safe direction (a window opens wider,
/// never narrower) — but past a day the deadline rule starts demanding escrows
/// nobody would fund. Checked before any money moves.
const MAX_ANCHOR_DRIFT_SECS: i64 = 86_400;

// ---- Paths, resolved against the manifest so the run works from any cwd ----

fn at(rel: &str) -> String {
    format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"))
}

/// The profile the game wasm is baked from. Read at runtime rather than mirrored
/// as constants: every one of these values enters `auction_id` or the escrow
/// address, so a stale copy here derives an id the canister refuses with
/// `AuctionIdMismatch` — a rejection with nothing in it to read.
struct Config {
    voting_period: u64,
    perform_window: u64,
    min_entry: u64,
    sign_price: u128,
    root_price: u128,
    fee_bps: u16,
    fee_wallet: [u8; 32],
    chain_id: String,
    factory: [u8; 32],
    domain: String,
    slot_ms: u64,
    genesis_slot: u64,
    genesis_unix: u64,
}

impl Config {
    fn load() -> R<Self> {
        let text = std::fs::read_to_string(at("../../config/testnet.toml"))?;
        Ok(Self {
            voting_period: cfg_u128(&text, "voting_period")? as u64,
            perform_window: cfg_u128(&text, "perform_window")? as u64,
            min_entry: cfg_u128(&text, "min_entry")? as u64,
            sign_price: cfg_u128(&text, "sign_price")?,
            root_price: cfg_u128(&text, "root_price")?,
            fee_bps: cfg_u128(&text, "fee_bps")? as u16,
            fee_wallet: cfg_addr(&text, "fee_wallet")?,
            chain_id: cfg_str(&text, "id")?,
            factory: cfg_addr(&text, "factory")?,
            domain: cfg_str(&text, "domain")?,
            slot_ms: cfg_u128(&text, "slot_ms")? as u64,
            genesis_slot: cfg_u128(&text, "genesis_slot")? as u64,
            genesis_unix: cfg_u128(&text, "genesis_unix")? as u64,
        })
    }

    /// The canister's `config::slot_to_created_at`, mirrored so the driver can
    /// pick a deadline the registration gate will accept.
    fn created_at(&self, slot: u64) -> Option<u64> {
        let elapsed = slot.checked_sub(self.genesis_slot)?;
        self.genesis_unix
            .checked_add(elapsed.checked_mul(self.slot_ms)? / 1_000)
    }
}

/// Same first-match-on-key rule as the games' `build.rs`, so the driver and the
/// wasm can never disagree about which line a key came from.
fn cfg_str(text: &str, key: &str) -> R<String> {
    text.lines()
        .find_map(|l| {
            let rest = l.trim().strip_prefix(key)?.trim_start().strip_prefix('=')?;
            let rest = rest.split('#').next().unwrap_or(rest).trim();
            Some(rest.trim_matches('"').to_string())
        })
        .ok_or_else(|| format!("missing `{key}` in config").into())
}

fn cfg_u128(text: &str, key: &str) -> R<u128> {
    let raw = cfg_str(text, key)?;
    Ok(raw.replace('_', "").parse()?)
}

fn cfg_addr(text: &str, key: &str) -> R<[u8; 32]> {
    let raw = cfg_str(text, key)?;
    bs58::decode(&raw)
        .into_vec()
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| format!("`{key}` = `{raw}` is not a Solana address").into())
}

// ---- SOL RPC `getTransaction` reply (candid mirror of `crown_indexer::parse`) ----
//
// Copied rather than imported so this binary does not link the index canister
// (two canister crates in one binary collide on `canister_init`).

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

/// Mirrors `crown-indexer.did` exactly.
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
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct BirthView {
    slot: u64,
    donor: Vec<u8>,
}

// ---- Small helpers ----

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

/// `force` is for the profile-baked game wasm: its bytes depend on `config/`, and
/// a cached artifact from an earlier config silently disagrees with the ids this
/// driver derives (a stale `fee_wallet` alone is an `AuctionIdMismatch` the
/// boundary refuses, with nothing to read but "rejected").
fn wasm(path: &str, dir: &str, extra: &[&str], td: Option<&str>, force: bool) -> Vec<u8> {
    if force || !std::path::Path::new(path).exists() {
        build(dir, extra, td);
    }
    std::fs::read(path).unwrap_or_else(|_| panic!("read wasm {path}"))
}

/// `<message>\n---\npubkey: ..\nsignature: ..\n<extras>` — the shared wire format.
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

/// `payer` funds the account and is the only signer; `owner` need not exist as a
/// wallet at all. Conflating the two would make a freshly generated recipient the
/// fee payer, and the transaction would want a signature nobody can give.
fn create_ata_idempotent(payer: &Pubkey, owner: &Pubkey) -> Instruction {
    spl_associated_token_account::instruction::create_associated_token_account_idempotent(
        payer,
        owner,
        &two_outcome::USDC_MINT,
        &spl_token::ID,
    )
}

/// `ChainId` as the index keys the book: `sha256("crown-chain:v1:" ‖ id)`.
fn chain_key(chain_id: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"crown-chain:v1:");
    h.update(chain_id.as_bytes());
    h.finalize().to_vec()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Relay `method` to `target` with `cycles` attached, returning the raw reply.
/// Ingress carries no cycles, so every paid call in the system goes this way.
fn relay(
    pic: &PocketIc,
    proxy: Principal,
    target: Principal,
    method: &str,
    inner: Vec<u8>,
    cycles: u128,
) -> R<Vec<u8>> {
    let arg = Encode!(&target, &method.to_string(), &inner, &cycles)?;
    let reply = pic
        .update_call(proxy, anon(), "relay", arg)
        .map_err(|e| format!("relay {method}: {e:?}"))?;
    let raw = Decode!(&reply, Vec<u8>)?;
    if raw.is_empty() {
        return Err(format!("relay {method}: the downstream call was rejected").into());
    }
    Ok(raw)
}

/// Wait for the transaction to finalize, then hand the index the **real** reply:
/// the raw transaction plus `meta.innerInstructions`, where a settlement's event
/// and its matching transfer live (both are CPIs — drop them and the index sees a
/// bare `donate`/`claim` and folds nothing).
///
/// The index only ever reads `finalized` (`00 §6`), so this waits for finality
/// rather than lowering the bar to `confirmed`: a reorg before finality means the
/// event never happened, and folding a merely-confirmed transaction would prove
/// nothing about the production path.
fn fetch_finalized(client: &RpcClient, sig: &str) -> R<MultiGetTransactionResult> {
    let cfg = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Base58),
        commitment: Some(CommitmentConfig::finalized()),
        max_supported_transaction_version: Some(0),
    };
    let parsed = sig.parse()?;
    let fetched = loop {
        match client.get_transaction_with_config(&parsed, cfg) {
            Ok(t) => break t,
            Err(_) => std::thread::sleep(std::time::Duration::from_secs(3)),
        }
    };
    let tx_b58 = match fetched.transaction.transaction {
        UiTx::Binary(s, _) => s,
        _ => return Err("expected a base58-encoded transaction".into()),
    };
    let meta = fetched
        .transaction
        .meta
        .ok_or("the finalized transaction carries no meta")?;
    let inner = match meta.inner_instructions {
        OptionSerializer::Some(groups) => Some(
            groups
                .into_iter()
                .map(|g| InnerInstructions {
                    index: g.index,
                    instructions: g
                        .instructions
                        .into_iter()
                        .filter_map(|ix| match ix {
                            UiInstruction::Compiled(c) => Some(Ix::compiled(CompiledInstruction {
                                data: c.data,
                                accounts: c.accounts,
                                programIdIndex: c.program_id_index,
                                stackHeight: c.stack_height,
                            })),
                            // `base58` encoding never yields parsed instructions;
                            // if it somehow did, the index could not read them
                            // either, so dropping them keeps the two in step.
                            UiInstruction::Parsed(_) => None,
                        })
                        .collect(),
                })
                .collect(),
        ),
        _ => None,
    };
    Ok(MultiGetTransactionResult::Consistent(
        GetTransactionResult::Ok(Some(TransactionReply {
            slot: fetched.slot,
            transaction: EncodedTxWithMeta {
                meta: Some(TxMeta {
                    status: TxStatus::Ok,
                    innerInstructions: inner,
                    loadedAddresses: None,
                }),
                transaction: EncodedTransaction::binary(tx_b58, Encoding::base58),
            },
        })),
    ))
}

/// Serve one real devnet transaction to the index through the mock and pay for
/// its ingest. Returns the fold counts and the slot the index recorded.
fn ingest(
    pic: &PocketIc,
    client: &RpcClient,
    mock: Principal,
    proxy: Principal,
    index: Principal,
    sig: &str,
) -> R<IngestResult> {
    let reply = fetch_finalized(client, sig)?;
    pic.update_call(mock, anon(), "set_reply", Encode!(&Encode!(&reply)?)?)
        .map_err(|e| format!("set_reply: {e:?}"))?;
    let raw = relay(
        pic,
        proxy,
        index,
        "ingest",
        Encode!(&sig.to_string())?,
        INGEST_PRICE,
    )?;
    Ok(Decode!(&raw, IngestResult)?)
}

fn reputation(
    pic: &PocketIc,
    index: Principal,
    chain: &[u8],
    donor: &[u8; 32],
    recipient: &[u8; 32],
) -> R<(u128, Vec<u8>)> {
    let q = pic
        .query_call(
            index,
            anon(),
            "get_reputation",
            Encode!(&chain.to_vec(), &donor.to_vec(), &recipient.to_vec())?,
        )
        .map_err(|e| format!("get_reputation: {e:?}"))?;
    let (n, witness) = Decode!(&q, Nat, Vec<u8>)?;
    let v = n.0.to_string().parse::<u128>()?;
    Ok((v, witness))
}

/// One escrow of the auction: everything derived before a lamport moves.
struct Entry {
    lot_hex: String,
    text_hash: [u8; 32],
    nonce: u64,
    resolver: [u8; 32],
    escrow: Pubkey,
    vault: Pubkey,
    salt: [u8; 32],
    create_sig: String,
}

fn main() -> R<()> {
    let cfg = Config::load()?;
    let client = RpcClient::new_with_commitment(URL.to_string(), CommitmentConfig::confirmed());
    let home = std::env::var("HOME")?;

    // The factory the game derives escrow addresses against must be the program
    // actually deployed on devnet, or every birth proof would look forged.
    if cfg.factory != two_outcome::ID.to_bytes() {
        return Err("config `factory` is not the deployed two-outcome program".into());
    }

    // ---- 0) wallets ----
    // The donor is the real funded devnet wallet; its ed25519 secret also signs
    // the register requests and the vote, so the on-chain payer, the wallet the
    // canister authenticates and the wallet the book credits are one key.
    let donor_kp = solana_sdk::signature::read_keypair_file(format!(
        "{home}/.config/solana/crown-index-e2e-donor.json"
    ))
    .map_err(|e| format!("read donor keypair: {e}"))?;
    let donor_sk = SigningKey::from_bytes(&donor_kp.to_bytes()[..32].try_into()?);
    let donor_pk = donor_kp.pubkey().to_bytes();
    let donor_ata = get_associated_token_address(&donor_kp.pubkey(), &two_outcome::USDC_MINT);

    let fee_wallet_kp = solana_sdk::signature::read_keypair_file(format!(
        "{home}/.config/solana/crown-fee-wallet.json"
    ))
    .map_err(|e| format!("read fee wallet: {e}"))?;
    if fee_wallet_kp.pubkey().to_bytes() != cfg.fee_wallet {
        return Err(
            "local fee wallet != config `fee_wallet` (the escrow address commits it)".into(),
        );
    }
    let fee_ata = get_associated_token_address(&fee_wallet_kp.pubkey(), &two_outcome::USDC_MINT);

    // The recipient is fresh per run: it must sign its own auction actions, and a
    // fresh key also means the vote weight this run measures is the reputation
    // this run bought — not a leftover from an earlier one.
    let recipient_kp = Keypair::new();
    let recipient_sk = SigningKey::from_bytes(&recipient_kp.to_bytes()[..32].try_into()?);
    let recipient = recipient_kp.pubkey().to_bytes();
    let recipient_ata =
        get_associated_token_address(&recipient_kp.pubkey(), &two_outcome::USDC_MINT);
    println!(
        "donor {} — {} USDC\nrecipient {} (fresh)",
        donor_kp.pubkey(),
        balance(&client, &donor_ata),
        recipient_kp.pubkey()
    );

    // ---- 1) the slot→time anchor, checked before any money moves ----
    // `created_at` is derived from the birth slot through the pinned anchor; a
    // stale anchor shuts the bidding window before the first registration and the
    // refusal reads as groundless. Cheap to check, expensive to discover later.
    let head_slot = client.get_slot()?;
    let head_time = client.get_block_time(head_slot)?;
    let modelled = cfg
        .created_at(head_slot)
        .ok_or("the head slot precedes the pinned anchor — the anchor is from the future")?;
    let drift = modelled as i64 - head_time;
    println!(
        "\n[1] slot→time anchor: slot {} → model {modelled}, chain {head_time} (drift {drift}s)",
        head_slot
    );
    if drift.abs() > MAX_ANCHOR_DRIFT_SECS {
        return Err(format!(
            "anchor drift {drift}s exceeds {MAX_ANCHOR_DRIFT_SECS}s — re-pin `config/*.toml`:\n\
             genesis_slot = {head_slot}\n\
             genesis_unix = {head_time}"
        )
        .into());
    }
    println!("    ✓ the model tracks the chain");

    // ---- 2) PocketIC: index + mock SOL RPC + relay proxy + auction(key_1) ----
    println!("\n[2] local IC: index + mock SOL RPC + relay proxy + auction(key_1)");
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_fiduciary_subnet()
        .with_application_subnet()
        .build();
    // Put the replica on the chain's clock. The auction's windows are half
    // chain-derived (`created_at`, from the birth slot) and half canister-derived
    // (`now`), and only agreeing clocks make the two comparable at all.
    let now_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    pic.set_time(Time::from_nanos_since_unix_epoch(now_unix * 1_000_000_000));
    let app = pic.topology().get_app_subnets()[0];

    let index = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(index, 5_000_000_000_000);
    pic.install_canister(
        index,
        wasm(
            &at("../../../../crown-indexer/target/wasm32-unknown-unknown/release/crown_indexer.wasm"),
            &at("../../../../crown-indexer"),
            &["--lib"],
            None,
            false,
        ),
        Encode!()?,
        None,
    );

    let mock = pic
        .create_canister_with_id(None, None, Principal::from_slice(&SOL_RPC))
        .expect("create mock at the SOL_RPC principal");
    pic.add_cycles(mock, 5_000_000_000_000);
    pic.install_canister(
        mock,
        wasm(
            &at("../../../e2e-fixtures/mock-sol-rpc/target/wasm32-unknown-unknown/release/mock_sol_rpc.wasm"),
            &at("../../../e2e-fixtures/mock-sol-rpc"),
            &[],
            None,
            false,
        ),
        Encode!()?,
        None,
    );

    let proxy = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(proxy, 100_000_000_000_000);
    pic.install_canister(
        proxy,
        wasm(
            &at("../../../e2e-fixtures/relay-proxy/target/wasm32-unknown-unknown/release/relay_proxy.wasm"),
            &at("../../../e2e-fixtures/relay-proxy"),
            &[],
            None,
            false,
        ),
        Encode!()?,
        None,
    );

    let game = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(game, 20_000_000_000_000);
    let init = Some(InitArgs {
        nns_root_key: pic.root_key().expect("nns root key"),
        index,
    });
    pic.install_canister(
        game,
        wasm(
            &at("../../target/e2e/wasm32-unknown-unknown/release/auction.wasm"),
            &at("../../canister"),
            &["-p", "auction"],
            Some(&at("../../target/e2e")),
            true,
        ),
        Encode!(&init)?,
        None,
    );
    let b = pic
        .update_call(game, anon(), "bootstrap", Encode!()?)
        .map_err(|e| format!("bootstrap: {e:?}"))?;
    if !matches!(Decode!(&b, AuctionResult)?, AuctionResult::KeyBootstrapped) {
        return Err("bootstrap did not take the master key".into());
    }
    println!("    ✓ threshold key bootstrapped (key_1)");

    // ---- 3) the voter buys its weight: a real direct donation ----
    // A vote weighs book reputation, and the only way into the book is an honest
    // settlement read from chain (`00 §9`, harness §1). So the voter donates for
    // real through the delimiter, and the index folds that transaction.
    println!("\n[3] devnet: splitter.donate → the voter's book weight");
    let chain = chain_key(&cfg.chain_id);
    let donate_ix = Instruction {
        program_id: two_outcome::SPLITTER,
        accounts: splitter::accounts::Donate {
            donor: donor_kp.pubkey(),
            donor_ata,
            recipient_ata,
            mint: two_outcome::USDC_MINT,
            token_program: spl_token::ID,
            event_authority: Pubkey::find_program_address(
                &[b"__event_authority"],
                &two_outcome::SPLITTER,
            )
            .0,
            program: two_outcome::SPLITTER,
        }
        .to_account_metas(None),
        data: splitter::instruction::Donate { gross: SEED_GROSS }.data(),
    };
    let seed_sig = send(
        &client,
        &donor_kp,
        &[
            create_ata_idempotent(&donor_kp.pubkey(), &recipient_kp.pubkey()),
            donate_ix,
        ],
    )?;
    println!("    donate tx {seed_sig}");
    match ingest(&pic, &client, mock, proxy, index, &seed_sig)? {
        IngestResult::Applied {
            settlements: 1,
            anomalies: 0,
            ..
        } => {}
        other => return Err(format!("the seed donation did not fold: {other:?}").into()),
    }
    let (weight, _) = reputation(&pic, index, &chain, &donor_pk, &recipient)?;
    if weight != SEED_GROSS as u128 {
        return Err(format!("book weight is {weight}, expected {SEED_GROSS}").into());
    }
    println!("    ✓ book credits the donor {weight} against this recipient");

    // ---- 4) derive the auction, its two lots and their escrow addresses ----
    // The escrow deadline must outlive the whole auction on both clocks: the
    // canister checks `deadline ≥ created_at + duration + perform + voting +
    // margin`, and `create_escrow` refuses a deadline already past on devnet.
    let deadline = head_time + 30 * 24 * 3600;
    let recipient_nonce = now_unix; // unique per run → a fresh auction each time
    let auction_id = protocol::auction_id(
        game.as_slice(),
        recipient,
        recipient_nonce,
        DURATION,
        cfg.perform_window,
        cfg.voting_period,
        cfg.min_entry,
    );
    let auction_hex = hex::encode(auction_id);
    println!("\n[4] auction {auction_hex}");

    let mut entries = Vec::new();
    for (label, nonce_bump) in [("a5-winning-bid", 0u64), ("a5-losing-bid", 1u64)] {
        let text_hash = sha256(label.as_bytes());
        let lot_id = protocol::lot_id(&auction_id, &text_hash);
        let lot_hex = hex::encode(lot_id);
        let nonce = now_unix + nonce_bump;
        // The per-entry resolver this escrow must commit. Asking the canister
        // rather than deriving it locally is the point: the address only works if
        // the key the game will sign under is the key baked into the escrow.
        let rq = pic
            .query_call(
                game,
                anon(),
                "get_resolver",
                Encode!(
                    &lot_hex,
                    &bs58::encode(donor_pk).into_string(),
                    &nonce,
                    &GROSS,
                    &deadline
                )?,
            )
            .map_err(|e| format!("get_resolver: {e:?}"))?;
        let resolver: [u8; 32] = bs58::decode(Decode!(&rq, Option<String>)?.ok_or("resolver")?)
            .into_vec()?
            .try_into()
            .map_err(|_| "resolver is not 32 bytes")?;
        let salt = crown_salt::two_outcome::two_outcome(
            donor_pk,
            recipient,
            GROSS,
            deadline,
            resolver,
            cfg.fee_bps,
            cfg.fee_wallet,
            nonce,
        );
        let (escrow_arr, _) = crown_derive::solana_pda_address(cfg.factory, &[b"escrow", &salt])
            .ok_or("derive escrow")?;
        let escrow = Pubkey::new_from_array(escrow_arr);
        println!("    lot {label}: escrow {escrow}");
        entries.push(Entry {
            lot_hex,
            text_hash,
            nonce,
            resolver,
            escrow,
            vault: get_associated_token_address(&escrow, &two_outcome::USDC_MINT),
            salt,
            create_sig: String::new(),
        });
    }

    // ---- 5) devnet: fund both escrows for real ----
    println!("\n[5] devnet: two create_escrow");
    for e in entries.iter_mut() {
        let ix = Instruction {
            program_id: two_outcome::ID,
            accounts: two_outcome::accounts::CreateEscrow {
                donor: donor_kp.pubkey(),
                escrow: e.escrow,
                vault: e.vault,
                donor_ata,
                mint: two_outcome::USDC_MINT,
                token_program: spl_token::ID,
                associated_token_program: spl_associated_token_account::ID,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
            data: two_outcome::instruction::CreateEscrow {
                salt: e.salt,
                recipient: Pubkey::new_from_array(recipient),
                gross: GROSS,
                deadline,
                resolver: Pubkey::new_from_array(e.resolver),
                fee_bps: cfg.fee_bps,
                fee_wallet: Pubkey::new_from_array(cfg.fee_wallet),
                nonce: e.nonce,
            }
            .data(),
        };
        e.create_sig = send(&client, &donor_kp, &[ix])?;
        let funded = balance(&client, &e.vault);
        if funded != GROSS {
            return Err(format!("vault holds {funded}, expected {GROSS}").into());
        }
        println!(
            "    create_escrow tx {} — vault funded {funded}",
            e.create_sig
        );
    }

    // ---- 6) the index folds both real transactions into births ----
    println!("\n[6] index: fold both real devnet transactions into births");
    for e in &entries {
        match ingest(&pic, &client, mock, proxy, index, &e.create_sig)? {
            IngestResult::Applied { births: 1, .. } => {}
            other => return Err(format!("expected one birth, got {other:?}").into()),
        }
    }
    println!("    ✓ two births recognized from the real transactions");

    // Both births are in, so the root has stopped moving: one paid push covers
    // every witness taken from here on (birth proofs and the vote's weight proof).
    let cq = pic
        .query_call(index, anon(), "get_certificate", Encode!()?)
        .map_err(|e| format!("get_certificate: {e:?}"))?;
    let cert = Decode!(&cq, Option<Vec<u8>>, Vec<u8>)?
        .0
        .ok_or("the index has no certificate")?;
    let pr = relay(
        &pic,
        proxy,
        game,
        "push_root",
        Encode!(&cert)?,
        cfg.root_price,
    )?;
    if !matches!(Decode!(&pr, AuctionResult)?, AuctionResult::RootPushed) {
        return Err("push_root did not authenticate the index root".into());
    }
    println!("    ✓ index root authenticated and cached (paid)");

    // ---- 7) register both entries as direct ingress ----
    println!("\n[7] register both entries (direct ingress)");
    for (i, e) in entries.iter().enumerate() {
        let bq = pic
            .query_call(
                index,
                anon(),
                "get_birth",
                Encode!(&e.escrow.to_bytes().to_vec())?,
            )
            .map_err(|err| format!("get_birth: {err:?}"))?;
        let witness = Decode!(&bq, Option<BirthView>, Vec<u8>)?.1;
        let msg = protocol::register_message(
            &cfg.chain_id,
            &game.to_text(),
            &auction_hex,
            &hex::encode(e.text_hash),
        );
        let extras = vec![
            ("recipient", bs58::encode(recipient).into_string()),
            ("recipient_nonce", recipient_nonce.to_string()),
            ("duration", DURATION.to_string()),
            ("perform_window", cfg.perform_window.to_string()),
            ("voting_period", cfg.voting_period.to_string()),
            ("min_entry", cfg.min_entry.to_string()),
            ("gross", GROSS.to_string()),
            ("deadline", deadline.to_string()),
            ("nonce", e.nonce.to_string()),
            ("witness", hex::encode(&witness)),
        ];
        let rr = pic
            .update_call(
                game,
                anon(),
                "register_entry",
                Encode!(&signed_request(&donor_sk, &msg, &extras))?,
            )
            .map_err(|err| format!("register_entry (direct ingress must be admitted): {err:?}"))?;
        // The first confirmed entry materializes the auction and fixes
        // `created_at` from its birth slot; the second is a plain registration.
        match (i, Decode!(&rr, AuctionResult)?) {
            (0, AuctionResult::Materialized) | (_, AuctionResult::Registered) => {}
            (_, other) => return Err(format!("register_entry: {other:?}").into()),
        }
    }
    let aq = pic
        .query_call(game, anon(), "get_auction", Encode!(&auction_hex)?)
        .map_err(|e| format!("get_auction: {e:?}"))?;
    if !matches!(
        Decode!(&aq, Option<AuctionStateView>)?,
        Some(AuctionStateView::Bidding)
    ) {
        return Err("the auction is not in Bidding after registration".into());
    }
    println!("    ✓ both entries registered against real births; auction is Bidding");

    // ---- 8) accept both lots → pick the winner → ready ----
    println!("\n[8] accept both lots → pick_winner → ready");
    for e in &entries {
        let msg = protocol::lot_message(
            "accept",
            &cfg.chain_id,
            &game.to_text(),
            &auction_hex,
            &e.lot_hex,
        );
        let rr = pic
            .update_call(
                game,
                anon(),
                "accept_lot",
                Encode!(&signed_request(&recipient_sk, &msg, &[]))?,
            )
            .map_err(|err| format!("accept_lot: {err:?}"))?;
        if !matches!(Decode!(&rr, AuctionResult)?, AuctionResult::Advanced(_)) {
            return Err("accept_lot did not advance the lot".into());
        }
    }
    let pick_msg = protocol::lot_message(
        "pick",
        &cfg.chain_id,
        &game.to_text(),
        &auction_hex,
        &entries[0].lot_hex,
    );
    let rr = pic
        .update_call(
            game,
            anon(),
            "pick_winner",
            Encode!(&signed_request(&recipient_sk, &pick_msg, &[]))?,
        )
        .map_err(|e| format!("pick_winner: {e:?}"))?;
    if !matches!(
        Decode!(&rr, AuctionResult)?,
        AuctionResult::Advanced(AuctionStateView::Performing)
    ) {
        return Err("pick_winner did not open Performing".into());
    }
    let ready_msg =
        protocol::auction_message("ready", &cfg.chain_id, &game.to_text(), &auction_hex);
    let rr = pic
        .update_call(
            game,
            anon(),
            "ready",
            Encode!(&signed_request(&recipient_sk, &ready_msg, &[]))?,
        )
        .map_err(|e| format!("ready: {e:?}"))?;
    if !matches!(
        Decode!(&rr, AuctionResult)?,
        AuctionResult::Advanced(AuctionStateView::Voting)
    ) {
        return Err("ready did not open Voting".into());
    }
    println!("    ✓ winner picked, work declared ready, voting open");

    // ---- 9) vote with the real book weight ----
    println!("\n[9] vote (weight = real book reputation, proven against the cached root)");
    let (_, weight_witness) = reputation(&pic, index, &chain, &donor_pk, &recipient)?;
    let vote_msg = protocol::vote_message(
        &cfg.chain_id,
        &game.to_text(),
        &auction_hex,
        &entries[0].lot_hex,
        "done",
    );
    let extras = vec![("weight_witness", hex::encode(&weight_witness))];
    let rr = pic
        .update_call(
            game,
            anon(),
            "vote",
            Encode!(&signed_request(&donor_sk, &vote_msg, &extras))?,
        )
        .map_err(|e| format!("vote (a valid vote must pass the boundary): {e:?}"))?;
    if !matches!(
        Decode!(&rr, AuctionResult)?,
        AuctionResult::Advanced(AuctionStateView::Voting)
    ) {
        return Err("the vote was not recorded".into());
    }
    println!("    ✓ vote recorded with weight {weight}");

    // ---- 10) the window closes → two verdicts under two leaf resolvers ----
    println!("\n[10] voting window closes → request_signature per entry");
    pic.advance_time(std::time::Duration::from_secs(cfg.voting_period + 1));
    let mut signatures = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let expected = if i == 0 { SETTLE } else { CANCEL };
        let raw = relay(
            &pic,
            proxy,
            game,
            "request_signature",
            Encode!(
                &cfg.chain_id,
                &auction_hex,
                &e.lot_hex,
                &bs58::encode(e.escrow.to_bytes()).into_string()
            )?,
            cfg.sign_price,
        )?;
        match Decode!(&raw, AuctionResult)? {
            AuctionResult::Signed { outcome, signature } => {
                if outcome != expected {
                    return Err(format!("entry {i}: outcome {outcome}, expected {expected}").into());
                }
                if signature.len() != 64 {
                    return Err("not a 64-byte Ed25519 signature".into());
                }
                // The same check the chain will make: `assert_resolver_signed`
                // verifies this signature against the escrow's own `resolver`
                // field. Two entries, two leaf resolvers — a settle can never be
                // redeemed against the sibling that must cancel.
                let mut verdict = cfg.domain.as_bytes().to_vec();
                verdict.extend_from_slice(&cfg.factory);
                verdict.push(outcome);
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&e.resolver)?;
                let sig = ed25519_dalek::Signature::from_slice(&signature)?;
                vk.verify_strict(&verdict, &sig).map_err(|_| {
                    "the verdict signature does not verify against the entry resolver"
                })?;
                println!(
                    "    ✓ entry {i}: outcome {outcome}, {}",
                    hex::encode(&signature)
                );
                signatures.push(signature);
            }
            other => return Err(format!("request_signature: {other:?}").into()),
        }
    }

    // ---- 11) devnet: claim the winner, cancel the loser ----
    println!("\n[11] devnet: claim(settle) for the winner, claim(cancel) for the loser");
    // Both payout ATAs must exist even for a cancel — `claim` resolves the
    // accounts before it knows the outcome.
    send(
        &client,
        &donor_kp,
        &[
            create_ata_idempotent(&donor_kp.pubkey(), &recipient_kp.pubkey()),
            create_ata_idempotent(&donor_kp.pubkey(), &fee_wallet_kp.pubkey()),
        ],
    )?;

    let fee = (GROSS as u128 * cfg.fee_bps as u128 / 10_000) as u64;
    let net = GROSS - fee;
    let recipient_before = balance(&client, &recipient_ata);
    let fee_before = balance(&client, &fee_ata);
    let donor_before = balance(&client, &donor_ata);

    let mut settle_sig = String::new();
    for (i, e) in entries.iter().enumerate() {
        let outcome = if i == 0 { SETTLE } else { CANCEL };
        let mut verdict = cfg.domain.as_bytes().to_vec();
        verdict.extend_from_slice(&cfg.factory);
        verdict.push(outcome);
        let claim_ix = Instruction {
            program_id: two_outcome::ID,
            accounts: two_outcome::accounts::Claim {
                caller: donor_kp.pubkey(),
                escrow: e.escrow,
                vault: e.vault,
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
            data: two_outcome::instruction::Claim { outcome }.data(),
        };
        let sig = send(
            &client,
            &donor_kp,
            &[ed25519_ix(&e.resolver, &signatures[i], &verdict), claim_ix],
        )?;
        println!("    claim tx {sig} (outcome {outcome})");
        if i == 0 {
            settle_sig = sig;
        }
        if !closed(&client, &e.vault) {
            return Err(format!("vault {} must be closed after claim", e.vault).into());
        }
    }

    let recipient_after = balance(&client, &recipient_ata);
    let fee_after = balance(&client, &fee_ata);
    let donor_after = balance(&client, &donor_ata);
    if recipient_after != recipient_before + net {
        return Err(format!(
            "recipient got {}, expected {net}",
            recipient_after - recipient_before
        )
        .into());
    }
    if fee_after != fee_before + fee {
        return Err(format!("fee wallet got {}, expected {fee}", fee_after - fee_before).into());
    }
    // The loser's whole gross comes back; the winner's leaves. The donor is the
    // same wallet for both, so the net movement is exactly the loser's refund.
    if donor_after != donor_before + GROSS {
        return Err(format!(
            "donor got back {}, expected the loser's {GROSS}",
            donor_after - donor_before
        )
        .into());
    }
    println!(
        "    ✓ recipient +{net}, fee wallet +{fee}, loser's donor +{GROSS}, both vaults closed"
    );

    // ---- 12) the settlement flows back into the book, to the donor ----
    println!("\n[12] index: fold the settlement → reputation lands on the donor");
    match ingest(&pic, &client, mock, proxy, index, &settle_sig)? {
        IngestResult::Applied {
            settlements: 1,
            anomalies: 0,
            ..
        } => {}
        other => return Err(format!("the settlement did not fold: {other:?}").into()),
    }
    let (after, _) = reputation(&pic, index, &chain, &donor_pk, &recipient)?;
    if after != SEED_GROSS as u128 + net as u128 {
        return Err(format!(
            "reputation is {after}, expected {}",
            SEED_GROSS as u128 + net as u128
        )
        .into());
    }
    // …and not to the escrow address, which is the silent, permanent failure mode
    // an index without the birth would fall into (`00 §4`).
    let (at_escrow, _) = reputation(
        &pic,
        index,
        &chain,
        &entries[0].escrow.to_bytes(),
        &recipient,
    )?;
    if at_escrow != 0 {
        return Err("the settlement was credited to the escrow address, not the donor".into());
    }
    println!("    ✓ donor reputation {after}; the escrow address holds none");

    println!("\nA5 PASSED — real escrows, real book weight, real threshold verdicts, real settle + refund on devnet.");
    Ok(())
}
