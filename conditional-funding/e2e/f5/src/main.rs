//! conditional-funding F5 — live devnet e2e.
//!
//! The property this game exists for, proven with money on both ends: **one**
//! verdict signature settles **every** escrow of a collection. Two real
//! collections run end to end on Solana devnet against a local index — one
//! approved by a vote whose weight is real book reputation, one cancelled by its
//! recipient — and in each the single threshold signature is redeemed by *both*
//! contributions. Nothing about the verdict, the vote weight or the escrow set is
//! simulated.
//!
//!   1. PocketIC: index + mock SOL RPC + relay proxy + funding (`key_1`);
//!   2. **devnet**: a real `splitter.donate` buys the voter its reputation — the
//!      only way the system allows (`00 §9`), folded from chain by the index;
//!   3. collection A: derive `collection_id` → one resolver → **two** escrow
//!      addresses (membership is derivation, not a registry — the second
//!      contribution never touches the canister);
//!   4. **devnet**: two `create_escrow`; both births folded by the index;
//!   5. `push_root` → `create_collection` (direct ingress, birth proof) → `ready`
//!      → **vote** with the book weight → the window closes → `Decided{Settle}`;
//!   6. paid `request_signature` → one real Ed25519 threshold signature; a repeat
//!      costs **zero** and a free `get_signature` hands out the same bytes — this
//!      is what turns the `s/N` amortization from a possibility into a fact;
//!   7. **devnet**: `claim(settle)` on **both** escrows with that one signature —
//!      recipient paid twice net, fee wallet twice fee, both vaults closed;
//!   8. collection B: the same shape, decided by `recipient_cancel` — one
//!      signature, `claim(refund)` on both escrows, both donors made whole;
//!   9. the settlements flow back into the book, crediting the **donor** and never
//!      the escrow address.
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
//!     cargo run --manifest-path crown-games/conditional-funding/e2e/f5/Cargo.toml

use anchor_lang::{InstructionData, ToAccountMetas};
use candid::{CandidType, Decode, Deserialize, Encode, Nat, Principal, Reserved};
use conditional_funding::{
    protocol, CollectionResult, CollectionStateView, InitArgs, SignatureView,
};
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
/// 1 USDC per contribution — over the game floor (`min_gross` = 0.41) and the
/// index dust floor (0.20), and small enough that a run costs little.
const GROSS: u64 = 250_000;
/// Contributions per collection. Two is the smallest N that can show the thing
/// worth showing: the second escrow redeems a signature it never paid for.
const N: usize = 2;
/// The reputation the voter buys itself: 0.5 USDC, over both `MIN_VOTE_WEIGHT`
/// (0.10) and the collection's `quorum_weight` (0.15) — turnout is one voter, so
/// the quorum has to be cleared by that voter alone.
const SEED_GROSS: u64 = 250_000;
/// One hour of funding — the run takes minutes, and a short window keeps the
/// escrow deadline rule (`+ voting + 72h margin`) modest.
const DURATION: u64 = 3_600;
/// Display only (`goal` gates nothing — spec §Тайминги).
const GOAL: u128 = 5_000_000;
const SETTLE: u8 = 0;
const REFUND: u8 = 1;
const SEP: &str = "\n---\n";
/// `crown-indexer/config/testnet.toml`. The index refuses anything below its own
/// price, and an `Underpaid` ingest folds nothing while looking like a no-op.
const INGEST_PRICE: u128 = 17_000_000_000;
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
/// as constants: every one of these values enters `collection_id` or the escrow
/// address, so a stale copy here derives an id the canister refuses with
/// `CollectionIdMismatch` — a rejection with nothing in it to read.
struct Config {
    voting_period: u64,
    approval_threshold: u16,
    quorum_weight: u128,
    min_gross: u64,
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
            approval_threshold: cfg_u128(&text, "approval_threshold")? as u16,
            quorum_weight: cfg_u128(&text, "quorum_weight")?,
            min_gross: cfg_u128(&text, "min_gross")? as u64,
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
/// driver derives (a stale `fee_wallet` alone is a `CollectionIdMismatch` the
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
/// its ingest.
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

/// One contribution: its escrow, derived before a lamport moves. All the
/// contributions of a collection share one `resolver` — that is what lets one
/// signature settle them all.
struct Contribution {
    nonce: u64,
    escrow: Pubkey,
    vault: Pubkey,
    salt: [u8; 32],
    create_sig: String,
}

/// Everything the driver derives for one collection before touching the chain.
struct Collection {
    id_hex: String,
    resolver: [u8; 32],
    recipient_nonce: u64,
    contributions: Vec<Contribution>,
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
    if (GROSS as u128) < cfg.min_gross as u128 {
        return Err("GROSS is below the game's own contribution floor".into());
    }

    // ---- 0) wallets ----
    // The donor is the real funded devnet wallet; its ed25519 secret also signs
    // the vote, so the on-chain payer, the wallet the canister authenticates and
    // the wallet the book credits are one key.
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

    // The recipient is fresh per run: it must sign its own collection actions, and
    // a fresh key also means the vote weight this run measures is the reputation
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
    // stale anchor shuts the funding window before the first materialization and
    // the refusal reads as groundless. Cheap to check, expensive to discover later.
    let head_slot = client.get_slot()?;
    let head_time = client.get_block_time(head_slot)?;
    let modelled = cfg
        .created_at(head_slot)
        .ok_or("the head slot precedes the pinned anchor — the anchor is from the future")?;
    let drift = modelled as i64 - head_time;
    println!("\n[1] slot→time anchor: slot {head_slot} → model {modelled}, chain {head_time} (drift {drift}s)");
    if drift.abs() > MAX_ANCHOR_DRIFT_SECS {
        return Err(format!(
            "anchor drift {drift}s exceeds {MAX_ANCHOR_DRIFT_SECS}s — re-pin `config/*.toml`:\n\
             genesis_slot = {head_slot}\n\
             genesis_unix = {head_time}"
        )
        .into());
    }
    println!("    ✓ the model tracks the chain");

    // ---- 2) PocketIC: index + mock SOL RPC + relay proxy + funding(key_1) ----
    println!("\n[2] local IC: index + mock SOL RPC + relay proxy + funding(key_1)");
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_fiduciary_subnet()
        .with_application_subnet()
        .build();
    // Put the replica on the chain's clock. A collection's window is half
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
            &at("../../target/e2e/wasm32-unknown-unknown/release/conditional_funding.wasm"),
            &at("../../canister"),
            &["-p", "conditional-funding"],
            Some(&at("../../target/e2e")),
            true,
        ),
        Encode!(&init)?,
        None,
    );
    let b = pic
        .update_call(game, anon(), "bootstrap", Encode!()?)
        .map_err(|e| format!("bootstrap: {e:?}"))?;
    if !matches!(
        Decode!(&b, CollectionResult)?,
        CollectionResult::KeyBootstrapped
    ) {
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
    if weight < cfg.quorum_weight {
        return Err(format!(
            "one voter carries {weight}, below the {} quorum — the vote could not decide",
            cfg.quorum_weight
        )
        .into());
    }
    println!(
        "    ✓ book credits the donor {weight} against this recipient (quorum {})",
        cfg.quorum_weight
    );

    // ---- 4) derive both collections and all their escrows ----
    // The escrow deadline must outlive the whole collection on both clocks: the
    // canister checks `deadline ≥ created_at + duration + voting + margin`, and
    // `create_escrow` refuses a deadline already past on devnet.
    let deadline = head_time + 30 * 24 * 3600;
    let mut collections = Vec::new();
    for (label, salt_bump) in [("approved", 0u64), ("cancelled", 100u64)] {
        let recipient_nonce = now_unix + salt_bump; // unique per run and per collection
        let id = protocol::collection_id(
            game.as_slice(),
            recipient,
            recipient_nonce,
            DURATION,
            cfg.voting_period,
            cfg.approval_threshold,
            cfg.quorum_weight,
        );
        let id_hex = hex::encode(id);
        // One resolver for the whole collection — asking the canister rather than
        // deriving it locally is the point: an escrow only belongs to a collection
        // because it committed *this* key, and membership is nothing else.
        let rq = pic
            .query_call(game, anon(), "get_resolver", Encode!(&id_hex)?)
            .map_err(|e| format!("get_resolver: {e:?}"))?;
        let resolver: [u8; 32] = bs58::decode(Decode!(&rq, Option<String>)?.ok_or("resolver")?)
            .into_vec()?
            .try_into()
            .map_err(|_| "resolver is not 32 bytes")?;

        let mut contributions = Vec::new();
        for i in 0..N {
            let nonce = recipient_nonce + i as u64 + 1;
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
            let (escrow_arr, _) =
                crown_derive::solana_pda_address(cfg.factory, &[b"escrow", &salt])
                    .ok_or("derive escrow")?;
            let escrow = Pubkey::new_from_array(escrow_arr);
            contributions.push(Contribution {
                nonce,
                escrow,
                vault: get_associated_token_address(&escrow, &two_outcome::USDC_MINT),
                salt,
                create_sig: String::new(),
            });
        }
        println!(
            "\n[4] collection {label} {id_hex}\n    resolver {} — {N} contributions",
            bs58::encode(resolver).into_string()
        );
        for c in &contributions {
            println!("    escrow {}", c.escrow);
        }
        collections.push(Collection {
            id_hex,
            resolver,
            recipient_nonce,
            contributions,
        });
    }

    // ---- 5) devnet: fund every escrow of both collections ----
    println!("\n[5] devnet: {} create_escrow", collections.len() * N);
    for col in collections.iter_mut() {
        for c in col.contributions.iter_mut() {
            let ix = Instruction {
                program_id: two_outcome::ID,
                accounts: two_outcome::accounts::CreateEscrow {
                    donor: donor_kp.pubkey(),
                    escrow: c.escrow,
                    vault: c.vault,
                    donor_ata,
                    mint: two_outcome::USDC_MINT,
                    token_program: spl_token::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_sdk::system_program::ID,
                }
                .to_account_metas(None),
                data: two_outcome::instruction::CreateEscrow {
                    salt: c.salt,
                    recipient: Pubkey::new_from_array(recipient),
                    gross: GROSS,
                    deadline,
                    resolver: Pubkey::new_from_array(col.resolver),
                    fee_bps: cfg.fee_bps,
                    fee_wallet: Pubkey::new_from_array(cfg.fee_wallet),
                    nonce: c.nonce,
                }
                .data(),
            };
            c.create_sig = send(&client, &donor_kp, &[ix])?;
            let funded = balance(&client, &c.vault);
            if funded != GROSS {
                return Err(format!("vault holds {funded}, expected {GROSS}").into());
            }
            println!(
                "    create_escrow tx {} — vault funded {funded}",
                c.create_sig
            );
        }
    }

    // ---- 6) the index folds every contribution's birth ----
    // Two different memberships, and it is easy to conflate them. The *game* only
    // ever learns about the first contribution — `create_collection` carries that
    // one proof and materializes; the rest are members by derivation alone, which
    // is exactly why one signature settles them all.
    //
    // The *book* is per-escrow. Attribution reads `escrow → donor` from the births
    // (`00 §4`), so a settlement paid by an escrow the index never saw is credited
    // to the escrow address instead of the human who funded it — silently and
    // permanently. So every contribution whose settlement should count needs its
    // own ingest, bought by whoever wants the reputation (`cost.md §8`).
    println!("\n[6] index: fold every contribution's birth");
    for col in &collections {
        for c in &col.contributions {
            match ingest(&pic, &client, mock, proxy, index, &c.create_sig)? {
                IngestResult::Applied { births: 1, .. } => {}
                other => return Err(format!("expected one birth, got {other:?}").into()),
            }
        }
    }
    println!(
        "    ✓ all {} births recognized from the real transactions",
        collections.len() * N
    );

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
    if !matches!(
        Decode!(&pr, CollectionResult)?,
        CollectionResult::RootPushed
    ) {
        return Err("push_root did not authenticate the index root".into());
    }
    println!("    ✓ index root authenticated and cached (paid)");

    // ---- 7) materialize both collections (direct ingress, recipient-signed) ----
    println!("\n[7] create_collection ×2 (direct ingress, against the real births)");
    for col in &collections {
        let first = &col.contributions[0];
        let bq = pic
            .query_call(
                index,
                anon(),
                "get_birth",
                Encode!(&first.escrow.to_bytes().to_vec())?,
            )
            .map_err(|e| format!("get_birth: {e:?}"))?;
        let witness = Decode!(&bq, Option<BirthView>, Vec<u8>)?.1;
        let msg =
            protocol::create_message(&cfg.chain_id, &game.to_text(), &col.id_hex, GOAL, DURATION);
        let extras = vec![
            ("recipient_nonce", col.recipient_nonce.to_string()),
            ("donor", bs58::encode(donor_pk).into_string()),
            ("gross", GROSS.to_string()),
            ("deadline", deadline.to_string()),
            ("nonce", first.nonce.to_string()),
            ("witness", hex::encode(&witness)),
        ];
        let rr = pic
            .update_call(
                game,
                anon(),
                "create_collection",
                Encode!(&signed_request(&recipient_sk, &msg, &extras))?,
            )
            .map_err(|e| format!("create_collection (direct ingress must be admitted): {e:?}"))?;
        if !matches!(
            Decode!(&rr, CollectionResult)?,
            CollectionResult::Materialized
        ) {
            return Err("create_collection did not materialize".into());
        }
        let gq = pic
            .query_call(game, anon(), "get_collection", Encode!(&col.id_hex)?)
            .map_err(|e| format!("get_collection: {e:?}"))?;
        if !matches!(
            Decode!(&gq, Option<CollectionStateView>)?,
            Some(CollectionStateView::Funding)
        ) {
            return Err("the collection is not in Funding after materialization".into());
        }
    }
    println!("    ✓ both collections materialized and funding");

    // ---- 8) collection A: ready → vote → the window closes → Settle ----
    println!("\n[8] collection A: ready → vote (real book weight) → Decided{{Settle}}");
    let a = &collections[0];
    let ready_msg = protocol::ready_message(&cfg.chain_id, &game.to_text(), &a.id_hex);
    let rr = pic
        .update_call(
            game,
            anon(),
            "ready",
            Encode!(&signed_request(&recipient_sk, &ready_msg, &[]))?,
        )
        .map_err(|e| format!("ready: {e:?}"))?;
    if !matches!(
        Decode!(&rr, CollectionResult)?,
        CollectionResult::Advanced(CollectionStateView::Voting)
    ) {
        return Err("ready did not open Voting".into());
    }
    let (_, weight_witness) = reputation(&pic, index, &chain, &donor_pk, &recipient)?;
    let vote_msg = protocol::vote_message(&cfg.chain_id, &game.to_text(), &a.id_hex, "done");
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
        Decode!(&rr, CollectionResult)?,
        CollectionResult::Advanced(CollectionStateView::Voting)
    ) {
        return Err("the vote was not recorded".into());
    }
    pic.advance_time(std::time::Duration::from_secs(cfg.voting_period + 1));
    println!("    ✓ vote recorded with weight {weight}, voting window closed");

    // ---- 9) collection B: the recipient cancels → Refund ----
    println!("\n[9] collection B: recipient_cancel → Decided{{Refund}}");
    let b_hex = collections[1].id_hex.clone();
    let cancel_msg = protocol::cancel_message(&cfg.chain_id, &game.to_text(), &b_hex);
    let rr = pic
        .update_call(
            game,
            anon(),
            "recipient_cancel",
            Encode!(&signed_request(&recipient_sk, &cancel_msg, &[]))?,
        )
        .map_err(|e| format!("recipient_cancel: {e:?}"))?;
    if !matches!(
        Decode!(&rr, CollectionResult)?,
        CollectionResult::Advanced(CollectionStateView::DecidedRefund)
    ) {
        return Err("recipient_cancel did not decide the collection as Refund".into());
    }
    println!("    ✓ all-or-nothing: the whole set refunds");

    // ---- 10) one paid signature per collection, then free forever ----
    println!("\n[10] request_signature ×2 → one real threshold verdict per collection");
    let mut verdicts = Vec::new();
    for (col, expected) in collections.iter().zip([SETTLE, REFUND]) {
        let raw = relay(
            &pic,
            proxy,
            game,
            "request_signature",
            Encode!(&cfg.chain_id, &col.id_hex)?,
            cfg.sign_price,
        )?;
        let signature = match Decode!(&raw, CollectionResult)? {
            CollectionResult::Signed { outcome, signature } => {
                if outcome != expected {
                    return Err(format!("outcome {outcome}, expected {expected}").into());
                }
                if signature.len() != 64 {
                    return Err("not a 64-byte Ed25519 signature".into());
                }
                signature
            }
            other => return Err(format!("request_signature: {other:?}").into()),
        };
        // The same check the chain will make: `assert_resolver_signed` verifies
        // this signature against each escrow's `resolver` field — and every escrow
        // of the collection carries the same one, which is the whole mechanism.
        let mut verdict = cfg.domain.as_bytes().to_vec();
        verdict.extend_from_slice(&cfg.factory);
        verdict.push(expected);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&col.resolver)?;
        let sig = ed25519_dalek::Signature::from_slice(&signature)?;
        vk.verify_strict(&verdict, &sig)
            .map_err(|_| "the verdict signature does not verify against the collection resolver")?;

        // A repeat is served from store with **zero** cycles attached, and the
        // free query hands the same bytes to every other escrow of the set. This
        // is what makes the `s/N` amortization a fact rather than a possibility
        // (`cost.md §6` #5): contribution 2..N never buys a signature at all.
        let again = relay(
            &pic,
            proxy,
            game,
            "request_signature",
            Encode!(&cfg.chain_id, &col.id_hex)?,
            0,
        )?;
        match Decode!(&again, CollectionResult)? {
            CollectionResult::Signed {
                outcome,
                signature: s2,
            } if outcome == expected && s2 == signature => {}
            other => {
                return Err(format!("a free repeat must return the same bytes: {other:?}").into())
            }
        }
        let gq = pic
            .query_call(game, anon(), "get_signature", Encode!(&col.id_hex)?)
            .map_err(|e| format!("get_signature: {e:?}"))?;
        let view = Decode!(&gq, Option<SignatureView>)?.ok_or("the signature is not stored")?;
        if view.outcome != expected || view.signature != signature {
            return Err("get_signature disagrees with the paid pull".into());
        }
        println!(
            "    ✓ {} → outcome {expected}, {} (repeat free, query agrees)",
            col.id_hex,
            hex::encode(&signature)
        );
        verdicts.push(signature);
    }

    // ---- 11) devnet: one signature, every escrow ----
    println!("\n[11] devnet: claim every escrow of both collections with its one signature");
    // Both payout ATAs must exist even for a refund — `claim` resolves the
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

    let mut settle_sigs = Vec::new();
    for (col, (outcome, signature)) in collections
        .iter()
        .zip([SETTLE, REFUND].into_iter().zip(verdicts.iter()))
    {
        let mut verdict = cfg.domain.as_bytes().to_vec();
        verdict.extend_from_slice(&cfg.factory);
        verdict.push(outcome);
        for c in &col.contributions {
            let claim_ix = Instruction {
                program_id: two_outcome::ID,
                accounts: two_outcome::accounts::Claim {
                    caller: donor_kp.pubkey(),
                    escrow: c.escrow,
                    vault: c.vault,
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
                &[ed25519_ix(&col.resolver, signature, &verdict), claim_ix],
            )?;
            println!(
                "    claim tx {sig} (outcome {outcome}, escrow {})",
                c.escrow
            );
            if outcome == SETTLE {
                settle_sigs.push(sig);
            }
            if !closed(&client, &c.vault) {
                return Err(format!("vault {} must be closed after claim", c.vault).into());
            }
        }
    }

    let n = N as u64;
    let recipient_after = balance(&client, &recipient_ata);
    let fee_after = balance(&client, &fee_ata);
    let donor_after = balance(&client, &donor_ata);
    if recipient_after != recipient_before + net * n {
        return Err(format!(
            "recipient got {}, expected {}",
            recipient_after - recipient_before,
            net * n
        )
        .into());
    }
    if fee_after != fee_before + fee * n {
        return Err(format!(
            "fee wallet got {}, expected {}",
            fee_after - fee_before,
            fee * n
        )
        .into());
    }
    // The cancelled collection returns every contribution in full.
    if donor_after != donor_before + GROSS * n {
        return Err(format!(
            "donor got back {}, expected the cancelled set's {}",
            donor_after - donor_before,
            GROSS * n
        )
        .into());
    }
    println!(
        "    ✓ one signature settled {N} escrows (recipient +{}, fee +{}) and one refunded {N} (donor +{})",
        net * n,
        fee * n,
        GROSS * n
    );

    // ---- 12) the settlements flow back into the book, to the donor ----
    println!("\n[12] index: fold both settlements → reputation lands on the donor");
    for sig in &settle_sigs {
        match ingest(&pic, &client, mock, proxy, index, sig)? {
            IngestResult::Applied {
                settlements: 1,
                anomalies: 0,
                ..
            } => {}
            other => return Err(format!("a settlement did not fold: {other:?}").into()),
        }
    }
    let (after, _) = reputation(&pic, index, &chain, &donor_pk, &recipient)?;
    let expected = SEED_GROSS as u128 + net as u128 * N as u128;
    if after != expected {
        return Err(format!("reputation is {after}, expected {expected}").into());
    }
    // …and not to the escrow addresses, which is the silent, permanent failure
    // mode an index missing a birth falls into (`00 §4`). Both contributions
    // settle, and both are credited to the human — that only holds because step 6
    // folded a birth for each, not just for the one the game was shown.
    for c in &collections[0].contributions {
        let (at_escrow, _) = reputation(&pic, index, &chain, &c.escrow.to_bytes(), &recipient)?;
        if at_escrow != 0 {
            return Err("a settlement was credited to an escrow address, not the donor".into());
        }
    }
    println!("    ✓ donor reputation {after}; no escrow address holds any");

    println!("\nF5 PASSED — real escrow sets, real book weight, one threshold verdict per collection, settle-all and refund-all on devnet.");
    Ok(())
}
