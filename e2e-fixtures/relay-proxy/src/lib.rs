//! Test fixture: relay a paid update call with attached cycles.
//!
//! Ingress messages cannot carry cycles (crown-relay CLAUDE.md), and a paid
//! `request_signature` is dropped by `inspect_message` on a direct ingress (its
//! multi-argument shape does not decode as the single signed `text` the boundary
//! expects). So the paid-pull invariants — `Underpaid`, "no charge without a
//! verdict", `WrongTarget` — are reachable only from an inter-canister caller that
//! attaches cycles. This canister is that caller: it forwards raw, pre-encoded args
//! to any method, so one fixture serves every game.

use candid::Principal;
use ic_cdk::call::Call;

/// Call `target.method(raw_args)` with `cycles` attached; return the raw candid
/// reply bytes (the test decodes the game's result type). An empty reply signals
/// the inter-canister call itself was rejected.
#[ic_cdk::update]
async fn relay(target: Principal, method: String, raw_args: Vec<u8>, cycles: u128) -> Vec<u8> {
    match Call::unbounded_wait(target, &method)
        .with_raw_args(&raw_args)
        .with_cycles(cycles)
        .await
    {
        Ok(reply) => reply.into_bytes(),
        Err(_) => Vec::new(),
    }
}
