//! Validate the blind birth proof's certificate chain against a *real*
//! crown-indexer certificate on a PocketIC replica: the BLS signature (with the
//! app-subnet delegation) verifies against the NNS root key, and the certified
//! data it commits to is exactly the combined root the index reports.
//!
//! Run with the bundled server:
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic cargo test --test birth_e2e

use candid::{Decode, Encode, Principal};
use conditional_tasks::birth::certified_root;
use pocket_ic::{PocketIc, PocketIcBuilder};

const INDEX_WASM: &str =
    "../../../crown-indexer/target/wasm32-unknown-unknown/release/crown_indexer.wasm";

fn index_wasm() -> Vec<u8> {
    if !std::path::Path::new(INDEX_WASM).exists() {
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "--lib",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
            ])
            .current_dir("../../../crown-indexer")
            .status()
            .expect("cargo build crown-indexer");
        assert!(status.success(), "failed to build the index wasm");
    }
    std::fs::read(INDEX_WASM).expect("read index wasm")
}

/// Install the real index on an application subnet under an NNS root.
fn setup() -> (PocketIc, Principal) {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let app = pic.topology().get_app_subnets()[0];
    let index = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(index, 4_000_000_000_000);
    pic.install_canister(index, index_wasm(), Encode!().unwrap(), None);
    (pic, index)
}

fn get_certificate(pic: &PocketIc, index: Principal) -> (Vec<u8>, Vec<u8>) {
    let bytes = pic
        .query_call(
            index,
            Principal::anonymous(),
            "get_certificate",
            Encode!().unwrap(),
        )
        .expect("get_certificate");
    let (cert, root) = Decode!(&bytes, Option<Vec<u8>>, Vec<u8>).unwrap();
    (cert.expect("a certificate is present"), root)
}

#[test]
fn a_real_index_certificate_authenticates_the_combined_root() {
    let (pic, index) = setup();
    let root_key = pic.root_key().expect("NNS root key");
    let (cert, reported_root) = get_certificate(&pic, index);

    // The BLS chain (delegation → subnet key → state-root signature) verifies,
    // and the certified data equals the root the index reported.
    let proven = certified_root(&cert, &root_key, index.as_slice())
        .expect("the certificate must verify against the NNS root key");
    assert_eq!(
        &proven[..],
        &reported_root[..],
        "certified root matches report"
    );
}

#[test]
fn a_wrong_root_key_is_rejected() {
    let (pic, index) = setup();
    let (cert, _) = get_certificate(&pic, index);
    // A bogus root key must not verify (BLS signature check fails).
    let bogus = vec![0u8; 96];
    assert!(certified_root(&cert, &bogus, index.as_slice()).is_none());
}

#[test]
fn a_wrong_canister_id_has_no_certified_data() {
    let (pic, index) = setup();
    let root_key = pic.root_key().expect("NNS root key");
    let (cert, _) = get_certificate(&pic, index);
    // Same (valid) certificate, but the path for another canister is absent.
    let other = Principal::anonymous();
    assert!(certified_root(&cert, &root_key, other.as_slice()).is_none());
}
