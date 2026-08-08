//! Full canister-game e2e (PocketIC): the birth-proof / signing path that needs a
//! real index + threshold key, without a live Solana RPC outcall. Mirrors the
//! reference game's `conditional-tasks/canister/tests/full_e2e.rs`.
//!
//! A mock SOL RPC canister at the index's pinned `SOL_RPC` principal returns a
//! synthetic `create_escrow` transaction, so a paid `ingest` (fronted by the relay
//! proxy with cycles) folds it into a **birth**. That birth is then consumed by
//! `register_entry` (a real donor-signed request + witness against a
//! `push_root`-cached index root) → materialize; then `cancel_auction` →
//! `request_signature` produces a real threshold `Signed{Cancel}` verdict under the
//! entry's own leaf resolver (`key([entry_id])`).
//!
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic cargo test --test full_e2e

use auction::{protocol, AuctionResult, AuctionStateView, InitArgs};
use candid::{CandidType, Decode, Deserialize, Encode, Principal, Reserved};
use ed25519_dalek::{Signer, SigningKey};
use pocket_ic::{PocketIc, PocketIcBuilder, Time};
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    transaction::Transaction,
};

const GAME_WASM: &str = "../target/e2e/wasm32-unknown-unknown/release/auction.wasm";
// **This auction's own `min_entry`** — a preimage field of `auction_id`, not the
// platform floor. The platform floor is `config::MIN_ENTRY` (`250_000` on the
// devnet profile), and the effective floor is `max(min_entry, MIN_ENTRY)`: a
// creator's field may only raise it. Named after neither on purpose, so the two
// do not get confused again — a test constant that mirrors baked config silently
// stops mirroring it when the config moves.
const MIN_ENTRY: u64 = 1_860_000;
// The fee is the game's price list, not a request field (harness §9): the escrow
// must be born with exactly these or it derives to a different address.
const FEE_BPS: u16 = 300;
// The fee wallet is the game's price list, not a request field (harness §9): the
// escrow must be born with exactly this one or it derives to another address.
const FEE_WALLET_B58: &str = "FS6ZNuPxXqWSGzwXEQpfoxikDksbEzmrXGZDFXmFj6vS";
const SIGN_PRICE: u128 = 26_200_000_000;
const ROOT_PRICE: u128 = 1_000_000_000;
const SEP: &str = "\n---\n";
// The devnet slot→time anchor and slope, same file. `created_at` comes from the
// birth slot through them, so the test has to invert the *pinned* anchor to land
// a birth inside the bidding window — a slot picked against a zero anchor now
// maps decades away and the auction is dead on materialization.
const SLOT_MS: u64 = 400;
const GENESIS_SLOT: u64 = 479_731_554;
const GENESIS_UNIX: u64 = 1_785_326_212;

/// Build the auction wasm into an isolated target dir — not to select a profile
/// (there is one devnet profile, `testnet`, and it names the key the replica
/// actually provisions), but so this nested `cargo build` never contends with the
/// outer `cargo test` for the workspace build lock.
///
/// Always invoked, never skipped on "the file is already there": these bytes
/// depend on `config/testnet.toml`, and an artifact cached from an earlier
/// config silently disagrees with the ids this test derives. A stale `fee_wallet`
/// alone moves every escrow address, so the birth proof lands nowhere and the
/// boundary drops a perfectly valid `register_entry` with nothing to read but
/// "rejected". Cargo no-ops when nothing changed, so the guard cost nothing and
/// bought a whole class of unexplainable failures.
fn game_wasm() -> Vec<u8> {
    {
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "-p",
                "auction",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "--target-dir",
                "../target/e2e",
            ])
            .status()
            .expect("build auction wasm");
        assert!(status.success());
    }
    std::fs::read(GAME_WASM).expect("read auction wasm")
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
    Decode!(&reply, Vec<u8>).expect("proxy returns raw reply bytes")
}

/// The whole IC-side flow, ending in a real threshold Ed25519 verdict signature
/// that verifies against the **entry's own** leaf resolver — everything but the
/// Solana claim, on a PocketIC replica.
#[test]
fn register_cancel_and_sign_a_real_verdict() {
    // Build the game wasm *before* the replica exists. The nested `cargo build` can
    // take a minute on a cold target dir, and an idle PocketIC instance gives up
    // waiting — a timeout that reads as a broken test rather than a slow one.
    let game_bytes = game_wasm();
    let (pic, index, mock, proxy) = setup();

    // Auction canister wired to THIS index + the replica root key.
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
        Decode!(&b, AuctionResult).unwrap(),
        AuctionResult::KeyBootstrapped
    ));

    // Auction parameters. The recipient opens the auction; a donor registers the
    // first entry (its birth is what materializes the auction).
    let recipient_sk = SigningKey::from_bytes(&[5u8; 32]);
    let recipient = recipient_sk.verifying_key().to_bytes();
    let donor_sk = SigningKey::from_bytes(&[9u8; 32]);
    let donor = donor_sk.verifying_key().to_bytes();
    let recipient_nonce = 1u64;
    let duration = 100_000u64;
    let gross = 2_000_000u64;
    let nonce = 7u64;
    // Far future (year ~2096): comfortably past the deadline rule's lower bound.
    let deadline = 4_000_000_000i64;
    let text_hash = [0xabu8; 32];

    let auction_id = protocol::auction_id(
        game.as_slice(),
        recipient,
        recipient_nonce,
        duration,
        MIN_ENTRY,
    );
    let auction_hex = hex::encode(auction_id);
    // The settlement scope is the **entry**, not the lot: `return_entry` splits the
    // outcomes of a lot's entries, so the resolver lives on the leaf.
    let lot_id = protocol::lot_id(&auction_id, &text_hash);
    let lot_hex = hex::encode(lot_id);
    let entry_id = protocol::entry_id(&lot_id, &donor, nonce, gross, deadline);

    // The per-entry resolver this escrow must commit (from the bootstrapped canister).
    let rq = pic
        .query_call(
            game,
            anon(),
            "get_resolver",
            Encode!(
                &lot_hex,
                &bs58::encode(donor).into_string(),
                &nonce,
                &gross,
                &deadline
            )
            .unwrap(),
        )
        .expect("get_resolver");
    let resolver: [u8; 32] = bs58::decode(Decode!(&rq, Option<String>).unwrap().expect("resolver"))
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    // The query derives exactly the leaf scope the canister will sign under.
    assert_eq!(
        entry_id,
        protocol::entry_id(&lot_id, &donor, nonce, gross, deadline),
        "entry_id is the per-entry leaf scope"
    );

    // The escrow address the birth must live at (= what register re-derives).
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

    // The bidding window anchors on the **birth slot**, not `now`
    // (`config::slot_to_created_at`): registration is frozen at
    // `T = created_at + duration`. So the slot must map to a `created_at` that is
    // actually inside the window on this replica.
    //
    // The replica's clock is pinned relative to the *anchor* rather than read from
    // the host: the anchor is a devnet fact from a particular day, and a replica
    // booted before it would put every real slot below `GENESIS_SLOT`, where
    // `slot_to_created_at` is `None` and the auction dies as `CreatedAtOverflow`.
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
        Encode!(&"sig-auction-1".to_string()).unwrap(),
        INGEST_PRICE,
    );
    assert!(
        matches!(
            Decode!(&ir, IngestResult).unwrap(),
            IngestResult::Applied { births: 1, .. }
        ),
        "ingest must fold exactly one birth"
    );

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

    // A donor-signed register + the unsigned birth-proof / field extras.
    let msg = protocol::register_message(
        "devnet",
        &game.to_text(),
        &auction_hex,
        &hex::encode(text_hash),
    );
    let extras = vec![
        ("recipient", bs58::encode(recipient).into_string()),
        ("recipient_nonce", recipient_nonce.to_string()),
        ("duration", duration.to_string()),
        ("min_entry", MIN_ENTRY.to_string()),
        ("gross", gross.to_string()),
        ("deadline", deadline.to_string()),
        ("nonce", nonce.to_string()),
        ("witness", hex::encode(&witness)),
    ];
    let register_text = signed_request(&donor_sk, &msg, &extras);

    // Before any root is pushed the witness has nothing to reconstruct into, so
    // the boundary refuses the very same request — for free, before any
    // replicated execution (`cost.md §6` #2).
    let early = pic.update_call(
        game,
        anon(),
        "register_entry",
        Encode!(&register_text).unwrap(),
    );
    assert!(
        early.is_err(),
        "no cached root → the boundary drops register_entry, it never executes"
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
            Decode!(&pr, AuctionResult).unwrap(),
            AuctionResult::RootPushed
        ),
        "the index certificate authenticates a root"
    );
    assert_price_covers_the_work(
        "push_root",
        before_root,
        pic.cycle_balance(game),
        ROOT_PRICE,
    );

    // Register as a **direct ingress** — what a real donor wallet sends. This is
    // the boundary contract: with the certificate's BLS moved to `push_root`, the
    // witness walk fits `inspect_message`, so the call is admitted and executes.
    let rr = pic
        .update_call(
            game,
            anon(),
            "register_entry",
            Encode!(&register_text).unwrap(),
        )
        .expect("direct ingress register_entry must be admitted");
    let res = Decode!(&rr, AuctionResult).unwrap();
    assert!(
        matches!(res, AuctionResult::Materialized),
        "register_entry must materialize the auction: {res:?}"
    );

    // The auction now exists (Bidding).
    let aq = pic
        .query_call(game, anon(), "get_auction", Encode!(&auction_hex).unwrap())
        .expect("get_auction");
    assert!(matches!(
        Decode!(&aq, Option<AuctionStateView>).unwrap(),
        Some(AuctionStateView::Bidding { .. })
    ));

    // Recipient cancels the auction → `Done{None}`; every entry resolves to Cancel
    // (a stuck auction never holds money).
    let cancel_msg = protocol::auction_message("cancel", "devnet", &game.to_text(), &auction_hex);
    let cancel_text = signed_request(&recipient_sk, &cancel_msg, &[]);
    let dr = pic
        .update_call(
            game,
            anon(),
            "cancel_auction",
            Encode!(&cancel_text).unwrap(),
        )
        .expect("cancel_auction admitted");
    assert!(
        matches!(
            Decode!(&dr, AuctionResult).unwrap(),
            AuctionResult::Advanced(AuctionStateView::Done { winner_lot: None })
        ),
        "cancel_auction ends the auction with no winner"
    );

    // Paid request_signature → a real threshold Ed25519 `Signed{Cancel}` verdict,
    // under the entry's own leaf scope.
    let escrow_b58 = bs58::encode(escrow_arr).into_string();
    let before_sign = pic.cycle_balance(game);
    let sr = relay(
        &pic,
        proxy,
        game,
        "request_signature",
        Encode!(&"devnet".to_string(), &auction_hex, &lot_hex, &escrow_b58).unwrap(),
        SIGN_PRICE,
    );
    let signature = match Decode!(&sr, AuctionResult).unwrap() {
        AuctionResult::Signed { outcome, signature } => {
            assert_eq!(outcome, 1, "cancel outcome");
            assert_eq!(signature.len(), 64, "a 64-byte Ed25519 signature");
            signature
        }
        other => panic!("expected Signed{{Cancel}}, got {other:?}"),
    };
    assert_price_covers_the_work(
        "request_signature",
        before_sign,
        pic.cycle_balance(game),
        SIGN_PRICE,
    );

    // The signature is a valid Ed25519 signature over the verdict message
    // `VERDICT_DOMAIN ‖ program_id(32) ‖ outcome` for **this entry's** resolver —
    // exactly what Solana's ed25519 program (and the two-outcome `claim`'s
    // `assert_resolver_signed`) checks. Verifying it here proves the on-chain claim
    // would accept it, and that it names this escrow and never a sibling entry.
    // This is the cross-chain link, D8.
    let mut verdict = b"crown:two-outcome:devnet".to_vec();
    verdict.extend_from_slice(&factory()); // program_id == crate::ID == config::FACTORY
    verdict.push(1u8); // cancel
    verdict.extend_from_slice(&FEE_BPS.to_le_bytes());
    verdict.extend_from_slice(&fee_wallet());
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&resolver)
        .expect("resolver is a valid Ed25519 public key");
    let sig = ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature");
    vk.verify_strict(&verdict, &sig)
        .expect("the threshold verdict signature verifies against the entry resolver");

    // The signature is memoized per entry: a repeat is served from store, free
    // (`cost.md §6` #5). Zero cycles attached.
    let again = relay(
        &pic,
        proxy,
        game,
        "request_signature",
        Encode!(&"devnet".to_string(), &auction_hex, &lot_hex, &escrow_b58).unwrap(),
        0,
    );
    match Decode!(&again, AuctionResult).unwrap() {
        AuctionResult::Signed {
            outcome,
            signature: s2,
        } => {
            assert_eq!(outcome, 1);
            assert_eq!(s2, signature, "the very same bytes, for free");
        }
        other => panic!("a repeat must be served from store for free, got {other:?}"),
    }

    // And the free query hands the same bytes to whoever lost the race.
    let gq = pic
        .query_call(
            game,
            anon(),
            "get_signature",
            Encode!(&auction_hex, &lot_hex, &escrow_b58).unwrap(),
        )
        .expect("get_signature");
    let view = Decode!(&gq, Option<auction::SignatureView>)
        .unwrap()
        .expect("signature is stored");
    assert_eq!(view.outcome, 1);
    assert_eq!(view.signature, signature);
}
