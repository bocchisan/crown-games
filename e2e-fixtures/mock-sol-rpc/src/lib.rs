//! Mock of the DFINITY SOL RPC canister for the game e2e: `getTransaction`
//! returns a reply set by the test (`set_reply`), so `crown-indexer::ingest` folds
//! a real/synthetic `create_escrow` transaction into a birth without a live
//! Solana RPC outcall.
//!
//! **Deliberately type-agnostic**, the same shape as `crown-indexer/e2e-mock`: the
//! test candid-encodes a `MultiGetTransactionResult` with the index's own types
//! and hands the raw bytes here, which `getTransaction` replies verbatim via
//! `msg_reply`. Exactness is unchanged — the encoder is still the index's own
//! type, it just runs in the test rather than in this canister.
//!
//! Typing the argument here would mean depending on the `crown-indexer` *canister*
//! crate, and a canister crate linked as a library brings its exported symbols
//! with it: every `#[query]`/`#[update]`, `init`, `post_upgrade`, and — sharpest —
//! `inspect_message`. This fixture did exactly that and silently inherited the
//! index's boundary, so when the index went fail-closed its own `set_reply` began
//! being refused by a hook this file never wrote. A test fixture must not link a
//! canister into a canister.

use candid::Reserved;
use std::cell::RefCell;

thread_local! {
    static REPLY: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Preload the raw candid bytes the next `getTransaction` will reply with.
#[ic_cdk::update]
fn set_reply(bytes: Vec<u8>) {
    REPLY.with(|r| *r.borrow_mut() = bytes);
}

/// The `getTransaction` the index calls. Arguments are ignored; the stored bytes
/// are replied raw, so this canister needs none of the index's response types.
#[ic_cdk::update(name = "getTransaction", manual_reply = true)]
fn get_transaction(_sources: Reserved, _config: Reserved, _params: Reserved) {
    let bytes = REPLY.with(|r| r.borrow().clone());
    ic_cdk::api::msg_reply(bytes);
}
