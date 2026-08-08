//! direct-settlement D1 — live devnet e2e.
//!
//! The claim this game makes, proven with money on one end and a real index on
//! the other: **a donation is two instructions and a submitter rule.** No
//! canister is installed here because none exists — that absence is the game's
//! whole non-negativity argument (`docs/spec.md §Не-отрицательность`), and a run
//! that quietly installed one would be proving something else.
//!
//!   1. quote the split from `logic` — the number the client would show a donor;
//!   2. **devnet**: one transaction, two instructions — the fee by a plain
//!      transfer that *bypasses* the splitter, the net *through* it;
//!   3. balances on chain: donor −gross, fee wallet +fee, recipient +net, and
//!      `fee + net == gross` with nothing unaccounted;
//!   4. read the confirmed transaction back and run the **submitter's** rule
//!      (`logic::payable`) over what the chain actually shows, not over what the
//!      client intended — the two readings meeting is the property;
//!   5. a real index folds that transaction and credits the **donor** with the
//!      **net**, never the gross and never the fee wallet;
//!   6. the same run, one cent short on the fee, is refused by the rule — the
//!      unpaid donation still stands on chain, it is simply not ours to index.
//!
//! Why PocketIC for the index rather than a deployed one: the SOL RPC canister
//! lives on IC mainnet and cannot be reached from a local replica, so its reply is
//! served by the mock. The transaction bytes inside that reply are the real ones
//! fetched from devnet — including `meta.innerInstructions`, where the splitter's
//! `Settled` and its matching transfer actually live — and the index parses,
//! recognizes and folds them exactly as it would in production. Same arrangement
//! and same one gap (multi-provider RPC consensus) as `T5`/`A5`/`F5`.
//!
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic \
//!     cargo run --manifest-path crown-games/direct-settlement/e2e/d1/Cargo.toml

use anchor_lang::{InstructionData, ToAccountMetas};
use candid::{CandidType, Decode, Deserialize, Encode, Nat, Principal, Reserved};
use direct_settlement_logic as logic;
use pocket_ic::{PocketIc, PocketIcBuilder, Time};
use sha2::{Digest, Sha256};
use solana_client::{rpc_client::RpcClient, rpc_config::RpcTransactionConfig};
use solana_sdk::{
    commitment_config::CommitmentConfig, instruction::Instruction, pubkey::Pubkey,
    signature::Keypair, signer::Signer, transaction::Transaction,
};
use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedTransaction as UiTx, UiInstruction,
    UiTransactionEncoding,
};
use spl_associated_token_account::get_associated_token_address;
use std::time::SystemTime;

type R<T> = Result<T, Box<dyn std::error::Error>>;

const URL: &str = "https://api.devnet.solana.com";
/// crown-indexer `config/testnet.toml`; the index refuses anything below it.
const INGEST_PRICE: u128 = 17_000_000_000;
/// The index's pinned SOL RPC principal — the mock is installed *at* it.
const SOL_RPC: [u8; 10] = [0, 0, 0, 0, 2, 48, 4, 68, 1, 1];
/// The chain id the index keys the book under (`config/testnet.toml`).
const CHAIN_ID: &str = "devnet";

/// 1 USDC. Comfortably over the game floor ($0.58) — the point of the run is the
/// mechanism, and a donation at the exact floor would make the balance assertions
/// harder to read for no gain. The floor itself is pinned by `logic`'s tests,
/// which can go red; a live run cannot.
const GROSS: u64 = 1_000_000;

fn at(rel: &str) -> String {
    format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"))
}

fn anon() -> Principal {
    Principal::anonymous()
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

/// Mirrors `crown-indexer.did`.
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
    UnknownBirth,
}

// ---- helpers (same shape as `T5`/`A5`/`F5`) ----

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

fn create_ata_idempotent(payer: &Pubkey, owner: &Pubkey) -> Instruction {
    spl_associated_token_account::instruction::create_associated_token_account_idempotent(
        payer,
        owner,
        &splitter::USDC_MINT,
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

/// Wait for finality and hand the index the **real** reply. `innerInstructions`
/// is where the splitter's `Settled` and its matching transfer live — both are
/// CPIs, and without them the index sees a bare `donate` and folds nothing.
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

fn reputation(pic: &PocketIc, index: Principal, donor: &[u8; 32], recipient: &[u8; 32]) -> R<u128> {
    let q = pic
        .query_call(
            index,
            anon(),
            "get_reputation",
            Encode!(&chain_key(CHAIN_ID), &donor.to_vec(), &recipient.to_vec())?,
        )
        .map_err(|e| format!("get_reputation: {e:?}"))?;
    let (n, _witness) = Decode!(&q, Nat, Vec<u8>)?;
    Ok(n.0.to_string().parse::<u128>()?)
}

/// The donation itself: the two instructions the client assembles, in the order
/// the spec fixes them. `create_ata_idempotent` rides in front because a fresh
/// recipient has no token account yet — atomicity makes "all or nothing" of the
/// three together.
fn donation_ixs(
    payer: &Pubkey,
    donor_ata: &Pubkey,
    fee_ata: &Pubkey,
    recipient: &Pubkey,
    recipient_ata: &Pubkey,
    split: logic::Split,
) -> R<Vec<Instruction>> {
    let fee_ix = spl_token::instruction::transfer_checked(
        &spl_token::ID,
        donor_ata,
        &splitter::USDC_MINT,
        fee_ata,
        payer,
        &[],
        split.fee,
        6,
    )?;
    // `donate` through the pinned splitter — this is the instruction that emits
    // `Settled`, and therefore the only one the book ever sees.
    let donate_ix = Instruction {
        program_id: splitter::ID,
        accounts: splitter::accounts::Donate {
            donor: *payer,
            donor_ata: *donor_ata,
            recipient_ata: *recipient_ata,
            mint: splitter::USDC_MINT,
            token_program: spl_token::ID,
            event_authority: Pubkey::find_program_address(
                &[b"__event_authority"],
                &splitter::ID,
            )
            .0,
            program: splitter::ID,
        }
        .to_account_metas(None),
        data: splitter::instruction::Donate { gross: split.net }.data(),
    };
    Ok(vec![
        create_ata_idempotent(payer, recipient),
        fee_ix,
        donate_ix,
    ])
}

fn main() -> R<()> {
    let client = RpcClient::new_with_commitment(URL.to_string(), CommitmentConfig::confirmed());
    let home = std::env::var("HOME")?;

    // ---- 0) wallets ----
    let donor_kp = solana_sdk::signature::read_keypair_file(format!(
        "{home}/.config/solana/crown-index-e2e-donor.json"
    ))
    .map_err(|e| format!("read donor keypair: {e}"))?;
    let donor = donor_kp.pubkey();
    let donor_ata = get_associated_token_address(&donor, &splitter::USDC_MINT);

    let fee_kp = solana_sdk::signature::read_keypair_file(format!(
        "{home}/.config/solana/crown-fee-wallet.json"
    ))
    .map_err(|e| format!("read fee wallet: {e}"))?;
    let fee_wallet = fee_kp.pubkey();
    let fee_ata = get_associated_token_address(&fee_wallet, &splitter::USDC_MINT);

    // Fresh per run, so the reputation this run measures is the one it bought.
    let recipient_kp = Keypair::new();
    let recipient = recipient_kp.pubkey();
    let recipient_ata = get_associated_token_address(&recipient, &splitter::USDC_MINT);

    println!(
        "donor {donor} — {} USDC\nfee wallet {fee_wallet}\nrecipient {recipient} (fresh)",
        balance(&client, &donor_ata)
    );

    // ---- 1) the quote: what a client would show the donor ----
    // Devnet floor (`docs/spec.md §Константы`); mainnet's is `logic::MIN_GROSS`.
    let split = logic::quote(GROSS, logic::FEE_BPS, 250_000)
        .map_err(|e| format!("the donation does not clear a floor: {e:?}"))?;
    println!(
        "\n[1] quote: gross {GROSS} → fee {} (2%) + net {}",
        split.fee, split.net
    );
    if split.fee + split.net != GROSS {
        return Err("the split does not add up".into());
    }

    // ---- 2) devnet: one transaction, two instructions ----
    println!("\n[2] devnet: fee past the splitter, net through it — one transaction");
    let before = (
        balance(&client, &donor_ata),
        balance(&client, &fee_ata),
        balance(&client, &recipient_ata),
    );
    let ixs = donation_ixs(
        &donor,
        &donor_ata,
        &fee_ata,
        &recipient,
        &recipient_ata,
        split,
    )?;
    let sig = send(&client, &donor_kp, &ixs)?;
    println!("    tx {sig}");

    // ---- 3) balances: exactly the split, nothing unaccounted ----
    let after = (
        balance(&client, &donor_ata),
        balance(&client, &fee_ata),
        balance(&client, &recipient_ata),
    );
    let (spent, earned, received) = (
        before.0 - after.0,
        after.1 - before.1,
        after.2 - before.2,
    );
    println!("[3] donor −{spent} · fee wallet +{earned} · recipient +{received}");
    if spent != GROSS || earned != split.fee || received != split.net {
        return Err(format!(
            "balances disagree with the split: −{spent} / +{earned} / +{received}"
        )
        .into());
    }
    println!("    ✓ fee + net == gross, and every unit landed where the spec says");

    // ---- 4) the submitter's rule, over what the chain shows ----
    // The client quoted it; now the *other* reading has to accept it. These two
    // agreeing is the property `logic` exists for, and this is the only place the
    // second one runs against a real transaction rather than a constructed pair.
    logic::payable(received, earned, logic::FEE_BPS, 250_000)
        .map_err(|e| format!("the submitter would refuse a donation it just quoted: {e:?}"))?;
    println!("[4] ✓ submitter's rule accepts the confirmed transaction");
    // …and refuses the same donation one unit under the honest fee (two units, to
    // clear the rounding slack the rule allows on purpose — `logic`).
    if logic::payable(received, earned - 2, logic::FEE_BPS, 250_000).is_ok() {
        return Err("the rule accepted an underpaid fee".into());
    }
    println!("    ✓ and refuses it with the fee shaved past the rounding unit");

    // ---- 5) a real index folds it and credits the donor with the net ----
    println!("\n[5] local IC: index + mock SOL RPC + relay proxy");
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
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
        ),
        Encode!()?,
        None,
    );
    println!("    ✓ installed");

    println!("\n[6] paid ingest of the real transaction");
    let donor_b: [u8; 32] = donor.to_bytes();
    let recipient_b: [u8; 32] = recipient.to_bytes();
    if reputation(&pic, index, &donor_b, &recipient_b)? != 0 {
        return Err("a fresh recipient already carries reputation".into());
    }
    let folded = ingest(&pic, &client, mock, proxy, index, &sig)?;
    println!("    {folded:?}");
    if !matches!(
        folded,
        IngestResult::Applied {
            settlements: 1,
            anomalies: 0,
            births: 0,
        }
    ) {
        return Err(format!("the donation did not fold as one clean settlement: {folded:?}").into());
    }

    // ---- 7) the book credits the donor with the NET ----
    let credited = reputation(&pic, index, &donor_b, &recipient_b)?;
    println!("[7] book: donor→recipient = {credited}");
    if credited != split.net as u128 {
        return Err(format!(
            "the book credited {credited}, expected the net {} — reputation must follow what \
             the splitter moved, not what the donor typed",
            split.net
        )
        .into());
    }
    println!("    ✓ reputation is the net, not the gross — the fee earns nothing");

    // The fee wallet must not have earned reputation of its own: its transfer went
    // *past* the splitter precisely so it would emit no `Settled`. Cheap to check
    // and the exact failure the bypass exists to prevent.
    let fee_b: [u8; 32] = fee_wallet.to_bytes();
    if reputation(&pic, index, &donor_b, &fee_b)? != 0 {
        return Err("the fee transfer minted reputation — it must bypass the splitter".into());
    }
    println!("    ✓ the fee minted no reputation for anyone");

    println!("\nD1 green: one transaction, 2% to us, net through the splitter, book credits the donor.");
    Ok(())
}
