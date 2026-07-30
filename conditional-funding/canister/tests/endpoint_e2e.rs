//! Endpoint-layer harness for the conditional-funding canister on a PocketIC
//! replica — the paid-pull `request_signature` invariants that unit tests over the
//! pure `state`/`verdict` helpers cannot reach.
//!
//! Ingress cannot attach cycles, and `request_signature` is dropped by
//! `inspect_message` on a direct ingress, so the payment gates are reachable only
//! from an inter-canister caller. The `relay-proxy` fixture (`crown-games/e2e-fixtures/relay-proxy`)
//! forwards the call with a chosen cycle amount and hands back the raw reply.
//!
//! Run with the bundled server:
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic cargo test --test endpoint_e2e
//!
//! Covered (no proof forging, no devnet): `request_signature` charges nothing
//! without a verdict (`Underpaid` below `SIGN_PRICE`, `WrongTarget` on a wrong
//! chain, `NotDecided` for an unknown/undecided collection); `inspect_message`
//! drops a malformed `vote`; queries wire through. Out of scope (needs proof
//! forging / devnet): birth-proof materialization, the vote weight-proof gate,
//! `Signed`/settle/refund money movement.

use candid::{Decode, Encode, Principal};
use conditional_funding::{CollectionResult, InitArgs};
use pocket_ic::{PocketIc, PocketIcBuilder};

const SIGN_PRICE: u128 = 26_200_000_000; // config/testnet.toml
const ROOT_PRICE: u128 = 1_000_000_000; // config/testnet.toml
const CHAIN: &str = "devnet";

const WASM: &str = "../target/wasm32-unknown-unknown/release/conditional_funding.wasm";
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

fn game_wasm() -> Vec<u8> {
    if !std::path::Path::new(WASM).exists() {
        build(".", &["-p", "conditional-funding"]);
    }
    std::fs::read(WASM).expect("read conditional-funding wasm")
}

fn proxy_wasm() -> Vec<u8> {
    if !std::path::Path::new(PROXY_WASM).exists() {
        build(PROXY_DIR, &[]);
    }
    std::fs::read(PROXY_WASM).expect("read relay-proxy wasm")
}

/// Install the game (testnet build → `init` override allowed) and the relay proxy
/// on one application subnet. Returns `(pic, game, proxy)`.
fn setup() -> (PocketIc, Principal, Principal) {
    let pic = PocketIcBuilder::new().with_application_subnet().build();
    let app = pic.topology().get_app_subnets()[0];

    let game = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(game, 4_000_000_000_000);
    let init = Some(InitArgs {
        nns_root_key: vec![0u8; 96],
        index: Principal::anonymous(),
    });
    pic.install_canister(game, game_wasm(), Encode!(&init).unwrap(), None);

    let proxy = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(proxy, 10_000_000_000_000);
    pic.install_canister(proxy, proxy_wasm(), Encode!().unwrap(), None);

    (pic, game, proxy)
}

/// Drive `request_signature(chain, collection)` through the proxy with `cycles`
/// attached and decode the `CollectionResult`.
fn request_signature(
    pic: &PocketIc,
    proxy: Principal,
    game: Principal,
    chain: &str,
    collection: &str,
    cycles: u128,
) -> CollectionResult {
    let inner = Encode!(&chain.to_string(), &collection.to_string()).unwrap();
    let arg = Encode!(&game, &"request_signature".to_string(), &inner, &cycles).unwrap();
    let reply = pic
        .update_call(proxy, Principal::anonymous(), "relay", arg)
        .expect("proxy relay call");
    let raw = Decode!(&reply, Vec<u8>).expect("proxy returns raw reply bytes");
    assert!(
        !raw.is_empty(),
        "the inter-canister call itself was rejected"
    );
    Decode!(&raw, CollectionResult).expect("decode CollectionResult")
}

/// Drive `push_root(cert)` through the proxy with `cycles` attached and decode
/// the `CollectionResult`.
fn push_root(
    pic: &PocketIc,
    proxy: Principal,
    game: Principal,
    cert: &[u8],
    cycles: u128,
) -> CollectionResult {
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
    Decode!(&raw, CollectionResult).expect("decode CollectionResult")
}

// A well-formed 32-byte hex collection id that names nothing.
fn unknown_collection() -> String {
    "00".repeat(32)
}

#[test]
fn an_unpaid_request_signature_does_no_work() {
    let (pic, game, proxy) = setup();
    let r = request_signature(&pic, proxy, game, CHAIN, &unknown_collection(), 0);
    assert!(matches!(r, CollectionResult::Underpaid), "got {r:?}");
}

#[test]
fn a_paid_call_to_the_wrong_chain_is_wrong_target() {
    let (pic, game, proxy) = setup();
    let r = request_signature(
        &pic,
        proxy,
        game,
        "mainnet-x",
        &unknown_collection(),
        SIGN_PRICE,
    );
    assert!(matches!(r, CollectionResult::WrongTarget), "got {r:?}");
}

#[test]
fn a_paid_call_for_an_undecided_collection_is_not_charged() {
    let (pic, game, proxy) = setup();
    // Paid, right chain, well-formed id, but the collection was never materialized →
    // `NotDecided` (no charge until the verdict is final).
    let r = request_signature(&pic, proxy, game, CHAIN, &unknown_collection(), SIGN_PRICE);
    assert!(matches!(r, CollectionResult::NotDecided), "got {r:?}");
}

#[test]
fn an_unpaid_push_root_does_no_work() {
    let (pic, game, proxy) = setup();
    // Below `ROOT_PRICE` the BLS pairings must not run at all: the cheapest,
    // most decisive check wins first (`cost.md §6` #2).
    let r = push_root(&pic, proxy, game, &[0u8; 64], 0);
    assert!(matches!(r, CollectionResult::Underpaid), "got {r:?}");
}

#[test]
fn a_paid_push_root_with_a_bogus_certificate_is_refused() {
    let (pic, game, proxy) = setup();
    // Paid, so the pairings run — and fail. Payment is accepted *before* the
    // pairings and is not refunded: fund-then-fail must not be cheaper than the
    // work it triggers (`01-standards §Тесты 4`).
    let r = push_root(&pic, proxy, game, b"not-a-certificate", ROOT_PRICE);
    assert!(matches!(r, CollectionResult::BadBirthProof), "got {r:?}");
}

#[test]
fn a_create_with_a_witness_but_no_cached_root_is_refused() {
    let (pic, game, _proxy) = setup();
    // The boundary trusts the `ROOTS` cache, never a caller-supplied certificate.
    // With no root pushed yet, a witness has nothing to reconstruct against, so a
    // create carrying one is refused — for free, before replicated execution.
    let text = format!(
        "action: create\nchain: {CHAIN}\ncanister: {game}\ncollection: {}\nduration: 3600\
         \n---\npubkey: 11111111111111111111111111111111\nsignature: 1111\
         \nrecipient_nonce: 1\nwitness: {}",
        unknown_collection(),
        "ab".repeat(64),
    );
    let res = pic.update_call(
        game,
        Principal::anonymous(),
        "create_collection",
        Encode!(&text).unwrap(),
    );
    assert!(
        res.is_err(),
        "no cached root → the boundary drops the create, it never executes"
    );
}

#[test]
fn inspect_message_drops_a_malformed_vote() {
    let (pic, game, _proxy) = setup();
    let arg = Encode!(&"not-a-valid-signed-vote".to_string()).unwrap();
    let res = pic.update_call(game, Principal::anonymous(), "vote", arg);
    assert!(res.is_err(), "inspect_message must drop the malformed vote");
}

#[test]
fn queries_wire_through() {
    let (pic, game, _proxy) = setup();

    let v = pic
        .query_call(
            game,
            Principal::anonymous(),
            "get_logic_version",
            Encode!().unwrap(),
        )
        .expect("get_logic_version");
    assert_eq!(Decode!(&v, u32).unwrap(), 3); // conditional-funding LOGIC_VERSION

    let g = pic
        .query_call(
            game,
            Principal::anonymous(),
            "get_collection",
            Encode!(&unknown_collection()).unwrap(),
        )
        .expect("get_collection");
    assert!(
        Decode!(&g, Option<conditional_funding::CollectionStateView>)
            .unwrap()
            .is_none()
    );
}
