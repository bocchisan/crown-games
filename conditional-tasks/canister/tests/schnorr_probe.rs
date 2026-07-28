//! Proof that the canister-game **signing path works** once the threshold-key name
//! matches what the replica provisions. pocket-ic-server 13 exposes Ed25519 Schnorr
//! under `key_1` (not `dfx_test_key`, which is a local-dfx-only name — and dfx 0.32
//! doesn't support Schnorr at all). Built with a `pocketic` config profile
//! (`threshold_key = "key_1"`), `bootstrap` derives the master key and `get_resolver`
//! returns a per-task resolver — the same key an escrow commits and a claim checks.
//!
//! Build the fixture wasm first:
//!   CROWN_PROFILE=pocketic cargo build -p conditional-tasks --release \
//!     --target wasm32-unknown-unknown
//!   cp .../conditional_tasks.wasm .../conditional_tasks_key1.wasm   # then restore testnet

use candid::{Decode, Encode, Principal};
use conditional_tasks::{InitArgs, TaskResult};
use pocket_ic::PocketIcBuilder;

// Built into an isolated target dir (own `CROWN_PROFILE`), so it never clobbers the
// normal testnet wasm nor contends for the outer test's build lock.
const KEY1_WASM: &str = "../target/pocketic/wasm32-unknown-unknown/release/conditional_tasks.wasm";

fn key1_wasm() -> Vec<u8> {
    if !std::path::Path::new(KEY1_WASM).exists() {
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "-p",
                "conditional-tasks",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "--target-dir",
                "../target/pocketic",
            ])
            .env("CROWN_PROFILE", "pocketic")
            .status()
            .expect("build conditional-tasks (pocketic profile)");
        assert!(status.success(), "pocketic-profile build failed");
    }
    std::fs::read(KEY1_WASM).expect("read key_1 wasm")
}

#[test]
fn bootstrap_and_resolver_work_with_the_provisioned_key() {
    let wasm = key1_wasm();
    // The fiduciary subnet holds the `key_1` threshold-Schnorr key.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_fiduciary_subnet()
        .with_application_subnet()
        .build();
    let app = pic.topology().get_app_subnets()[0];
    let game = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(game, 10_000_000_000_000);
    let init = Some(InitArgs {
        nns_root_key: vec![0u8; 96],
        index: Principal::anonymous(),
    });
    pic.install_canister(game, wasm, Encode!(&init).unwrap(), None);

    // bootstrap derives the master key from `key_1`.
    let reply = pic
        .update_call(
            game,
            Principal::anonymous(),
            "bootstrap",
            Encode!().unwrap(),
        )
        .expect("bootstrap call");
    let r = Decode!(&reply, TaskResult).unwrap();
    assert!(
        matches!(r, TaskResult::KeyBootstrapped),
        "bootstrap must succeed with the provisioned key: {r:?}"
    );

    // A per-task resolver is now derivable — the value an escrow commits on Solana.
    let task = bs58::encode([7u8; 32]).into_string();
    let q = pic
        .query_call(
            game,
            Principal::anonymous(),
            "get_resolver",
            Encode!(&task).unwrap(),
        )
        .expect("get_resolver");
    let resolver: Option<String> = Decode!(&q, Option<String>).unwrap();
    assert!(
        resolver.is_some(),
        "a bootstrapped canister must derive a per-task resolver"
    );
}
