//! Mock of the DFINITY SOL RPC canister for the index e2e: `getTransaction`
//! returns a reply set by the test (`set_reply`), so `crown-indexer::ingest` folds
//! a real/synthetic `create_escrow` transaction into a birth without a live
//! Solana RPC outcall. Reuses `crown_indexer::parse` types so the candid the index
//! decodes matches exactly.

use candid::Reserved;
use crown_indexer::parse::MultiGetTransactionResult;
use std::cell::RefCell;

thread_local! {
    static REPLY: RefCell<Option<MultiGetTransactionResult>> = const { RefCell::new(None) };
}

/// Preload the reply the next `getTransaction` will return.
#[ic_cdk::update]
fn set_reply(reply: MultiGetTransactionResult) {
    REPLY.with(|r| *r.borrow_mut() = Some(reply));
}

/// The index calls `getTransaction(sources, opt config, params)`; we ignore the
/// arguments and return the preloaded reply.
#[ic_cdk::update(name = "getTransaction")]
fn get_transaction(_sources: Reserved, _config: Reserved, _params: Reserved) -> MultiGetTransactionResult {
    REPLY.with(|r| r.borrow().clone().expect("call set_reply before getTransaction"))
}
