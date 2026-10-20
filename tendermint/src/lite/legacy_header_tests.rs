//! Header-hash compatibility with bnb-chain/tendermint v0.31.17 (SRC-1706).
use super::TmHeaderVerifier;
use prost_amino::Message;
use tendermint_proto::crypto::{
    BlockId, Consensus, Header, PartSetHeader, SignedHeader, Timestamp,
};

fn header(version: Option<Consensus>) -> Header {
    Header {
        version,
        chain_id: "src1706-test".into(),
        height: 42,
        time: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        num_txs: 3,
        total_txs: 7,
        last_block_id: Some(BlockId {
            hash: vec![1; 32],
            part_set_header: Some(PartSetHeader {
                total: 1,
                hash: vec![2; 32],
            }),
        }),
        last_commit_hash: vec![3; 32],
        data_hash: vec![4; 32],
        validators_hash: vec![5; 32],
        next_validators_hash: vec![6; 32],
        consensus_hash: vec![7; 32],
        app_hash: vec![8; 32],
        last_results_hash: vec![9; 32],
        evidence_hash: vec![10; 32],
        proposer_address: vec![11; 20],
    }
}

#[test]
fn version_hashes_match_go() {
    // Independently generated with Go Header.Hash() for the header above.
    let cases = [
        (
            None,
            "141cb39ce79097f3281bfd5657f47a38459a93c61e9809800ccca2d0313a7cf6",
        ),
        (
            Some(Consensus { block: 0, app: 0 }),
            "141cb39ce79097f3281bfd5657f47a38459a93c61e9809800ccca2d0313a7cf6",
        ),
        (
            Some(Consensus { block: 10, app: 0 }),
            "bcbfe9d98e392af1a1dc5f0c17a2f2460b91710a3c63ea7b44db7cd0d15b8613",
        ),
        (
            Some(Consensus { block: 10, app: 2 }),
            "298c287adab5fe365be5954eba9d869896c7ab8e8709af9c8aa90759c0b12b2c",
        ),
    ];
    for (version, expected) in cases {
        let signed_header = SignedHeader {
            header: Some(header(version)),
            commit: None,
        };
        assert_eq!(
            hex::encode(TmHeaderVerifier::hash_header(&signed_header).unwrap()),
            expected
        );
    }
}

#[test]
fn omitted_and_explicit_zero_versions_decode_to_the_same_hash() {
    let mut hashes = Vec::new();
    for version in [None, Some(Consensus::default())] {
        let original = header(version);
        let mut wire = Vec::new();
        original.encode_length_delimited(&mut wire).unwrap();
        let decoded = Header::decode_length_delimited(wire.as_slice()).unwrap();
        // Exercise the actual optional-message decoder, including an omitted field.
        assert_eq!(decoded.version, original.version);
        hashes.push(
            TmHeaderVerifier::hash_header(&SignedHeader {
                header: Some(decoded),
                commit: None,
            })
            .unwrap(),
        );
    }
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(
        hex::encode(hashes[0]),
        "141cb39ce79097f3281bfd5657f47a38459a93c61e9809800ccca2d0313a7cf6"
    );
}
