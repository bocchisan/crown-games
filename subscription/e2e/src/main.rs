//! subscription S1 — live devnet e2e for the `stream` form.
//!
//! Drives the deployed `stream` program (`81HsKu3F…`) on Solana devnet through
//! all three exit paths, with the funded `crown-index-e2e-donor` wallet:
//!   1. release — the full schedule pays each chunk through the splitter to the
//!      recipient (minus fee to `fee_wallet`); the last chunk settles + closes;
//!   2. cancel — a donor-signed ed25519 message drains the remainder to the donor;
//!   3. refund — permissionless after the overdue margin, remainder to the donor.
//!
//! Read-only unit/litesvm coverage is `crown-factory/shapes/stream/solana/tests`;
//! this is the real-network counterpart (build-plan S1). Run:
//!   cargo run --manifest-path crown-games/subscription/e2e/Cargo.toml

use anchor_lang::{InstructionData, ToAccountMetas};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    ed25519_program,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address;
use std::error::Error;

const URL: &str = "https://api.devnet.solana.com";
const CHUNK: u64 = 1_000_000; // 1 USDC (6 decimals)
const N_CHUNKS: u16 = 2;
const GROSS: u64 = CHUNK * N_CHUNKS as u64;
const FEE_BPS: u16 = 300;

type R<T> = Result<T, Box<dyn Error>>;

fn program() -> Pubkey {
    stream::ID
}
fn mint() -> Pubkey {
    stream::USDC_MINT
}
fn ata(owner: &Pubkey) -> Pubkey {
    get_associated_token_address(owner, &mint())
}

fn now(client: &RpcClient) -> R<i64> {
    // Devnet clock via the latest slot's block time.
    let slot = client.get_slot()?;
    Ok(client.get_block_time(slot)?)
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
        .and_then(|b| b.amount.parse::<u64>().ok())
        .unwrap_or(0)
}

fn closed(client: &RpcClient, addr: &Pubkey) -> bool {
    // A closed ATA has no account (or zero lamports).
    client
        .get_account(addr)
        .map(|a| a.lamports == 0)
        .unwrap_or(true)
}

/// Build & fund an escrow: a single-recipient (100%) stream over the given
/// schedule. Returns `(escrow, vault)`.
#[allow(clippy::too_many_arguments)]
fn create(
    client: &RpcClient,
    donor: &Keypair,
    recipient: &Pubkey,
    fee_wallet: &Pubkey,
    t0: i64,
    period: i64,
    nonce: u64,
) -> R<(Pubkey, Pubkey)> {
    let salt = crown_salt::stream::stream(
        donor.pubkey().to_bytes(),
        1,
        &[recipient.to_bytes()],
        &[10_000u16],
        CHUNK,
        N_CHUNKS,
        t0,
        period,
        FEE_BPS,
        fee_wallet.to_bytes(),
        nonce,
    );
    let (escrow, _) = crown_derive::solana_pda_address(program().to_bytes(), &[b"escrow", &salt])
        .ok_or("escrow PDA derivation failed")?;
    let escrow = Pubkey::new_from_array(escrow);
    let vault = ata(&escrow);
    let ix = Instruction {
        program_id: program(),
        accounts: stream::accounts::CreateEscrow {
            donor: donor.pubkey(),
            escrow,
            vault,
            donor_ata: ata(&donor.pubkey()),
            mint: mint(),
            token_program: spl_token::ID,
            associated_token_program: spl_associated_token_account::ID,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
        data: stream::instruction::CreateEscrow {
            salt,
            k: 1,
            recipients: vec![*recipient],
            shares: vec![10_000],
            chunk: CHUNK,
            n_chunks: N_CHUNKS,
            t0,
            period,
            fee_bps: FEE_BPS,
            fee_wallet: *fee_wallet,
            nonce,
        }
        .data(),
    };
    let sig = send(client, donor, &[ix])?;
    println!("    create_escrow tx {sig}");
    Ok((escrow, vault))
}

fn create_ata_ix(payer: &Pubkey, owner: &Pubkey) -> Instruction {
    spl_associated_token_account::instruction::create_associated_token_account(
        payer,
        owner,
        &mint(),
        &spl_token::ID,
    )
}

fn release_ix(caller: &Pubkey, escrow: &Pubkey, vault: &Pubkey, fee_ata: &Pubkey, donor: &Pubkey, rec_ata: &Pubkey, k: u16) -> Instruction {
    let (ev, _) = Pubkey::find_program_address(&[b"__event_authority"], &stream::SPLITTER);
    let mut accounts = stream::accounts::Release {
        caller: *caller,
        escrow: *escrow,
        vault: *vault,
        fee_wallet_ata: *fee_ata,
        donor: *donor,
        donor_ata: ata(donor),
        mint: mint(),
        token_program: spl_token::ID,
        splitter_program: stream::SPLITTER,
        splitter_event_authority: ev,
    }
    .to_account_metas(None);
    accounts.push(AccountMeta::new(*rec_ata, false));
    Instruction { program_id: program(), accounts, data: stream::instruction::Release { k }.data() }
}

fn refund_ix(caller: &Pubkey, escrow: &Pubkey, vault: &Pubkey, donor: &Pubkey) -> Instruction {
    Instruction {
        program_id: program(),
        accounts: stream::accounts::Refund {
            caller: *caller,
            escrow: *escrow,
            vault: *vault,
            donor: *donor,
            donor_ata: ata(donor),
            mint: mint(),
            token_program: spl_token::ID,
        }
        .to_account_metas(None),
        data: stream::instruction::Refund {}.data(),
    }
}

fn cancel_message(escrow: &Pubkey) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(stream::CANCEL_DOMAIN.as_bytes());
    m.extend_from_slice(stream::ID.as_ref());
    m.extend_from_slice(escrow.as_ref());
    m.push(0x01);
    m
}

/// A self-contained Ed25519Program instruction proving `signer` signed `message`.
fn ed25519_ix(signer: &Keypair, message: &[u8]) -> Instruction {
    let sig = signer.sign_message(message);
    let pk = signer.pubkey().to_bytes();
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
    d.extend_from_slice(&pk);
    d.extend_from_slice(sig.as_ref());
    d.extend_from_slice(message);
    Instruction { program_id: ed25519_program::ID, accounts: vec![], data: d }
}

fn cancel_ix(caller: &Pubkey, escrow: &Pubkey, vault: &Pubkey, donor: &Pubkey) -> Instruction {
    Instruction {
        program_id: program(),
        accounts: stream::accounts::Cancel {
            caller: *caller,
            escrow: *escrow,
            vault: *vault,
            donor: *donor,
            donor_ata: ata(donor),
            mint: mint(),
            token_program: spl_token::ID,
            instructions: solana_sdk::sysvar::instructions::ID,
        }
        .to_account_metas(None),
        data: stream::instruction::Cancel {}.data(),
    }
}

fn assert_eq_u64(what: &str, got: u64, want: u64) -> R<()> {
    if got == want {
        println!("    ✓ {what}: {got}");
        Ok(())
    } else {
        Err(format!("{what}: got {got}, want {want}").into())
    }
}

fn main() -> R<()> {
    let client = RpcClient::new_with_commitment(URL.to_string(), CommitmentConfig::confirmed());
    let home = std::env::var("HOME")?;
    let donor = solana_sdk::signature::read_keypair_file(format!(
        "{home}/.config/solana/crown-index-e2e-donor.json"
    ))
    .map_err(|e| format!("read donor keypair: {e}"))?;
    let donor_ata = ata(&donor.pubkey());
    println!("donor {} — {} USDC", donor.pubkey(), balance(&client, &donor_ata));

    let fee_per = CHUNK * FEE_BPS as u64 / 10_000; // 30_000
    let net_per = CHUNK - fee_per; // 970_000

    // ---- 1) release: full schedule pays through the splitter, then settles ----
    println!("\n[1] release → splitter distribution + settle");
    let recipient = Keypair::new().pubkey();
    let fee_wallet = Keypair::new().pubkey();
    let rec_ata = ata(&recipient);
    let fee_ata = ata(&fee_wallet);
    send(&client, &donor, &[create_ata_ix(&donor.pubkey(), &recipient), create_ata_ix(&donor.pubkey(), &fee_wallet)])?;
    let t0 = now(&client)? - 10; // both chunks already due
    let (escrow, vault) = create(&client, &donor, &recipient, &fee_wallet, t0, 1, 1)?;
    assert_eq_u64("vault funded", balance(&client, &vault), GROSS)?;
    for k in 0..N_CHUNKS {
        let sig = send(&client, &donor, &[release_ix(&donor.pubkey(), &escrow, &vault, &fee_ata, &donor.pubkey(), &rec_ata, k)])?;
        println!("    release({k}) tx {sig}");
    }
    assert_eq_u64("recipient net", balance(&client, &rec_ata), net_per * N_CHUNKS as u64)?;
    assert_eq_u64("fee_wallet fee", balance(&client, &fee_ata), fee_per * N_CHUNKS as u64)?;
    if !closed(&client, &vault) {
        return Err("vault must be closed after the last chunk".into());
    }
    println!("    ✓ vault settled + closed");

    // ---- 2) cancel: donor-signed ed25519 drains the remainder to the donor ----
    println!("\n[2] cancel → donor-signed refund of the remainder");
    let before = balance(&client, &donor_ata);
    let (escrow, vault) = create(&client, &donor, &recipient, &fee_wallet, now(&client)? - 10, 1, 2)?;
    assert_eq_u64("vault funded", balance(&client, &vault), GROSS)?;
    let ed = ed25519_ix(&donor, &cancel_message(&escrow));
    let sig = send(&client, &donor, &[ed, cancel_ix(&donor.pubkey(), &escrow, &vault, &donor.pubkey())])?;
    println!("    cancel tx {sig}");
    assert_eq_u64("donor refunded (whole gross back)", balance(&client, &donor_ata), before)?;
    if !closed(&client, &vault) {
        return Err("vault must be closed after cancel".into());
    }
    println!("    ✓ vault cancelled + closed");

    // ---- 3) refund: permissionless after the overdue margin ----
    println!("\n[3] refund → permissionless after the overdue margin");
    let before = balance(&client, &donor_ata);
    // t0 far in the past (> RELEASE_MARGIN=72h) so the refund bound is passed.
    let (escrow, vault) = create(&client, &donor, &recipient, &fee_wallet, now(&client)? - 300_000, 1, 3)?;
    assert_eq_u64("vault funded", balance(&client, &vault), GROSS)?;
    let sig = send(&client, &donor, &[refund_ix(&donor.pubkey(), &escrow, &vault, &donor.pubkey())])?;
    println!("    refund tx {sig}");
    assert_eq_u64("donor refunded (whole gross back)", balance(&client, &donor_ata), before)?;
    if !closed(&client, &vault) {
        return Err("vault must be closed after refund".into());
    }
    println!("    ✓ vault refunded + closed");

    println!("\nALL SCENARIOS PASSED on devnet.");
    Ok(())
}
