//! Endpoint-layer harness for the auction canister on a PocketIC replica — the
//! paid-pull `request_signature` invariants that unit tests over the pure
//! `state`/`resolve` helpers cannot reach.
//!
//! Ingress cannot attach cycles, and `request_signature` (four args) is dropped by
//! `inspect_message` on a direct ingress, so the payment gates are reachable only
//! from an inter-canister caller. The `relay-proxy` fixture (`crown-games/e2e-fixtures/relay-proxy`)
//! is that caller; it forwards the call with a chosen cycle amount and hands back
//! the raw reply for us to decode.
//!
//! Run with the bundled server:
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic cargo test --test endpoint_e2e
//!
//! What is covered (no proof forging, no devnet): `request_signature` charges
//! nothing without a verdict (`Underpaid` below `SIGN_PRICE`, `WrongTarget` on a
//! wrong chain, `NotFound` for an unknown auction); `inspect_message` drops a
//! malformed `vote` ingress before execution; and the queries wire through.
//! Still out of scope (needs proof forging / devnet): birth-proof `register_entry`,
//! the vote weight-proof gate, and `Signed`/settle/refund money movement.

use auction::{AuctionResult, InitArgs};
use candid::{Decode, Encode, Principal};
use pocket_ic::{PocketIc, PocketIcBuilder};

const SIGN_PRICE: u128 = 26_200_000_000; // config/testnet.toml
const ROOT_PRICE: u128 = 1_000_000_000; // config/testnet.toml
const CHAIN: &str = "devnet";

const AUCTION_WASM: &str = "../target/wasm32-unknown-unknown/release/auction.wasm";
const PROXY_DIR: &str = "../../e2e-fixtures/relay-proxy";
const PROXY_WASM: &str =
    "../../e2e-fixtures/relay-proxy/target/wasm32-unknown-unknown/release/relay_proxy.wasm";

fn build(dir: &str, extra: &[&str]) {
    let mut args = vec!["build", "--release", "--target", "wasm32-unknown-unknown"];
    args.extend_from_slice(extra);
    let status = std::process::Command::new("cargo")
        .args(&args)
        .current_dir(dir)
        .status()
        .expect("cargo build");
    assert!(status.success(), "failed to build {dir}");
}

fn auction_wasm() -> Vec<u8> {
    if !std::path::Path::new(AUCTION_WASM).exists() {
        build(".", &["-p", "auction"]);
    }
    std::fs::read(AUCTION_WASM).expect("read auction wasm")
}

fn proxy_wasm() -> Vec<u8> {
    if !std::path::Path::new(PROXY_WASM).exists() {
        build(PROXY_DIR, &[]);
    }
    std::fs::read(PROXY_WASM).expect("read relay-proxy wasm")
}

/// Install the auction canister (testnet build → the `init` override is allowed)
/// and the relay proxy on one application subnet. Returns `(pic, auction, proxy)`.
fn setup() -> (PocketIc, Principal, Principal) {
    let pic = PocketIcBuilder::new().with_application_subnet().build();
    let app = pic.topology().get_app_subnets()[0];

    let auction = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(auction, 4_000_000_000_000);
    // The stored index / root key are only read during proof verification, which
    // these tests never reach; placeholders keep `init` happy on testnet.
    let init = Some(InitArgs {
        nns_root_key: vec![0u8; 96],
        index: Principal::anonymous(),
    });
    pic.install_canister(auction, auction_wasm(), Encode!(&init).unwrap(), None);

    let proxy = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(proxy, 10_000_000_000_000);
    pic.install_canister(proxy, proxy_wasm(), Encode!().unwrap(), None);

    (pic, auction, proxy)
}

/// Drive `request_signature` through the proxy with `cycles` attached and decode
/// the `AuctionResult`.
#[allow(clippy::too_many_arguments)] // a thin test relay mirroring the 4-id call + cycles
fn request_signature(
    pic: &PocketIc,
    proxy: Principal,
    auction: Principal,
    chain: &str,
    auction_id: &str,
    lot: &str,
    escrow: &str,
    cycles: u128,
) -> AuctionResult {
    let inner = Encode!(
        &chain.to_string(),
        &auction_id.to_string(),
        &lot.to_string(),
        &escrow.to_string()
    )
    .unwrap();
    let arg = Encode!(&auction, &"request_signature".to_string(), &inner, &cycles).unwrap();
    let reply = pic
        .update_call(proxy, Principal::anonymous(), "relay", arg)
        .expect("proxy relay call");
    let raw = Decode!(&reply, Vec<u8>).expect("proxy returns raw reply bytes");
    assert!(
        !raw.is_empty(),
        "the inter-canister call itself was rejected"
    );
    Decode!(&raw, AuctionResult).expect("decode AuctionResult")
}

/// Drive `push_root(cert)` through the proxy with `cycles` attached and decode
/// the `AuctionResult`.
fn push_root(
    pic: &PocketIc,
    proxy: Principal,
    game: Principal,
    cert: &[u8],
    cycles: u128,
) -> AuctionResult {
    let inner = Encode!(&cert.to_vec()).unwrap();
    let arg = Encode!(&game, &"push_root".to_string(), &inner, &cycles).unwrap();
    let reply = pic
        .update_call(proxy, Principal::anonymous(), "relay", arg)
        .expect("proxy relay call");
    let raw = Decode!(&reply, Vec<u8>).expect("proxy returns raw reply bytes");
    assert!(
        !raw.is_empty(),
        "the inter-canister call itself was rejected"
    );
    Decode!(&raw, AuctionResult).expect("decode AuctionResult")
}

// Well-formed ids that parse (32-byte hex / base58) but name nothing.
fn ids() -> (String, String, String) {
    let auction_id = "00".repeat(32);
    let lot = "11".repeat(32);
    let escrow = bs58::encode([2u8; 32]).into_string();
    (auction_id, lot, escrow)
}

#[test]
fn an_unpaid_request_signature_does_no_work() {
    let (pic, auction, proxy) = setup();
    let (a, l, e) = ids();
    // Below `SIGN_PRICE` (here zero) → `Underpaid`, before any parsing or signing.
    let r = request_signature(&pic, proxy, auction, CHAIN, &a, &l, &e, 0);
    assert!(matches!(r, AuctionResult::Underpaid), "got {r:?}");
}

#[test]
fn a_paid_call_to_the_wrong_chain_is_wrong_target() {
    let (pic, auction, proxy) = setup();
    let (a, l, e) = ids();
    // Paid, but the chain does not match → `WrongTarget`, and nothing is charged
    // (the accept happens only past the verdict).
    let r = request_signature(&pic, proxy, auction, "mainnet-x", &a, &l, &e, SIGN_PRICE);
    assert!(matches!(r, AuctionResult::WrongTarget), "got {r:?}");
}

#[test]
fn a_paid_call_for_an_unknown_auction_is_not_found() {
    let (pic, auction, proxy) = setup();
    let (a, l, e) = ids();
    // Paid, right chain, well-formed ids, but the auction was never materialized →
    // `NotFound`, still no charge (a self-signed action never materializes).
    let r = request_signature(&pic, proxy, auction, CHAIN, &a, &l, &e, SIGN_PRICE);
    assert!(matches!(r, AuctionResult::NotFound), "got {r:?}");
}

#[test]
fn an_unpaid_push_root_does_no_work() {
    let (pic, auction, proxy) = setup();
    // Below `ROOT_PRICE` the BLS pairings must not run at all: the cheapest,
    // most decisive check wins first (`cost.md §6` #2).
    let r = push_root(&pic, proxy, auction, &[0u8; 64], 0);
    assert!(matches!(r, AuctionResult::Underpaid), "got {r:?}");
}

#[test]
fn a_paid_push_root_with_a_bogus_certificate_is_refused() {
    let (pic, auction, proxy) = setup();
    // Paid, so the pairings run — and fail. Payment is accepted *before* the
    // pairings and is not refunded: fund-then-fail must not be cheaper than the
    // work it triggers (`01-standards §Тесты 4`).
    let r = push_root(&pic, proxy, auction, b"not-a-certificate", ROOT_PRICE);
    assert!(matches!(r, AuctionResult::BadBirthProof), "got {r:?}");
}

#[test]
fn a_register_entry_with_a_witness_but_no_cached_root_is_refused() {
    let (pic, auction, _proxy) = setup();
    // The boundary trusts the `ROOTS` cache, never a caller-supplied certificate.
    // With no root pushed yet, a witness has nothing to reconstruct against, so a
    // registration carrying one is refused — for free, before replicated execution.
    let (a, _l, _e) = ids();
    let text = format!(
        "action: register\nchain: {CHAIN}\ncanister: {auction}\nauction: {a}\
         \ntext_hash: {}\n---\npubkey: 11111111111111111111111111111111\
         \nsignature: 1111\ngross: 1000000\ndeadline: 4000000000\nnonce: 1\nwitness: {}",
        "cd".repeat(32),
        "ab".repeat(64),
    );
    let res = pic.update_call(
        auction,
        Principal::anonymous(),
        "register_entry",
        Encode!(&text).unwrap(),
    );
    assert!(
        res.is_err(),
        "no cached root → the boundary drops register_entry, it never executes"
    );
}

#[test]
fn inspect_message_drops_a_malformed_vote() {
    let (pic, auction, _proxy) = setup();
    // A `vote` whose payload is not an admissible signed request is rejected at the
    // boundary — the update never runs (the non-negativity invariant: an invalid
    // vote does not reach paid execution).
    let arg = Encode!(&"not-a-valid-signed-vote".to_string()).unwrap();
    let res = pic.update_call(auction, Principal::anonymous(), "vote", arg);
    assert!(res.is_err(), "inspect_message must drop the malformed vote");
}

#[test]
fn queries_wire_through() {
    let (pic, auction, _proxy) = setup();

    let v = pic
        .query_call(
            auction,
            Principal::anonymous(),
            "get_logic_version",
            Encode!().unwrap(),
        )
        .expect("get_logic_version");
    assert_eq!(Decode!(&v, u32).unwrap(), 1);

    // An unknown auction has no state view.
    let (a, _, _) = ids();
    let g = pic
        .query_call(
            auction,
            Principal::anonymous(),
            "get_auction",
            Encode!(&a).unwrap(),
        )
        .expect("get_auction");
    assert!(Decode!(&g, Option<auction::AuctionStateView>)
        .unwrap()
        .is_none());
}
