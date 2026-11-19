//! Regression tests for legacy per-entry vote commitments (SRC-1704).
use super::{SignerLookup, TmHeaderVerifier, Validator};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
use prost_amino::Message;
use sha2::{Digest, Sha256};
use tendermint_proto::crypto::{
    BlockId, CanonicalBlockId, CanonicalPartSetHeader, CanonicalVote, Commit, CommitSig, Header,
    PartSetHeader, SignedHeader, Timestamp,
};

fn block_id() -> BlockId {
    BlockId {
        hash: vec![1; 32],
        part_set_header: Some(PartSetHeader {
            total: 1,
            hash: vec![2; 32],
        }),
    }
}

fn vote(block_id: Option<BlockId>) -> CommitSig {
    CommitSig {
        vote_type: 2,
        height: 42,
        round: 3,
        block_id,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        ..Default::default()
    }
}

// Construct the expected signed message independently of non_absent_vote.
fn canonical_vote(block: Option<BlockId>) -> CanonicalVote {
    let block = block.unwrap_or_default();
    let parts = block.part_set_header.unwrap_or_default();
    CanonicalVote {
        signed_msg_type: 2,
        height: 42,
        round: 3,
        block_id: if block.hash.is_empty() {
            None
        } else {
            Some(CanonicalBlockId {
                hash: block.hash,
                part_set_header: Some(CanonicalPartSetHeader {
                    total: parts.total,
                    hash: parts.hash,
                }),
            })
        },
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        chain_id: "src1704-test".into(),
    }
}

fn sign_bytes(vote: CanonicalVote) -> Vec<u8> {
    let mut bytes = Vec::new();
    vote.encode_length_delimited(&mut bytes).unwrap();
    bytes
}

#[test]
fn per_entry_vote_bytes_match_go() {
    // Vote.SignBytes from bnb-chain/tendermint v0.31.17, for nil and full BlockIDs.
    let cases = [
        (None, "2a0802112a000000000000001903000000000000002a060880e2cfaa06320c737263313730342d74657374"),
        (Some(block_id()), "740802112a0000000000000019030000000000000022480a20010101010101010101010101010101010101010101010101010101010101010112240a20020202020202020202020202020202020202020202020202020202020202020210012a060880e2cfaa06320c737263313730342d74657374"),
    ];
    for (block, expected) in cases {
        let actual =
            TmHeaderVerifier::non_absent_vote(&vote(block), "src1704-test".into()).unwrap();
        assert_eq!(hex::encode(sign_bytes(actual)), expected);
    }
}

#[test]
fn nil_block_id_encodings_are_equivalent() {
    let nil = sign_bytes(canonical_vote(None));
    for block in [
        None,
        Some(BlockId::default()),
        Some(BlockId {
            hash: vec![],
            part_set_header: Some(PartSetHeader::default()),
        }),
    ] {
        let actual =
            TmHeaderVerifier::non_absent_vote(&vote(block), "src1704-test".into()).unwrap();
        assert_eq!(sign_bytes(actual), nil);
    }
    assert!(
        TmHeaderVerifier::non_absent_vote(&CommitSig::default(), "src1704-test".into()).is_none()
    );
}

fn signed_commit(blocks: Vec<Option<BlockId>>) -> (SignedHeader, Vec<Validator>) {
    let mut validators = Vec::new();
    let signatures = blocks
        .into_iter()
        .enumerate()
        .map(|(index, block)| {
            let secret = SecretKey::from_bytes(&[index as u8 + 1; 32]).unwrap();
            let public = PublicKey::from(&secret);
            let key = Keypair { secret, public };
            let pub_key = key.public.to_bytes().to_vec();
            let address = Sha256::digest(&pub_key)[..20].to_vec();
            validators.push(Validator {
                pub_key,
                voting_power: 1,
            });
            let signature = key
                .sign(&sign_bytes(canonical_vote(block.clone())))
                .to_bytes()
                .to_vec();
            CommitSig {
                validator_address: address,
                signature,
                validator_index: index as i32,
                ..vote(block)
            }
        })
        .collect();
    (
        SignedHeader {
            header: Some(Header {
                chain_id: "src1704-test".into(),
                height: 42,
                ..Default::default()
            }),
            commit: Some(Commit {
                block_id: Some(block_id()),
                signatures,
            }),
        },
        validators,
    )
}

fn stray_blocks() -> Vec<Option<BlockId>> {
    let mut other_hash = block_id();
    other_hash.hash = vec![3; 32];
    let mut other_parts_hash = block_id();
    other_parts_hash.part_set_header.as_mut().unwrap().hash = vec![4; 32];
    let mut other_parts_total = block_id();
    other_parts_total.part_set_header.as_mut().unwrap().total = 2;
    vec![
        None,
        Some(BlockId::default()),
        Some(other_hash),
        Some(other_parts_hash),
        Some(other_parts_total),
    ]
}

// The vote checks and tally are shared by the slot (untrusted set) and address (trusted set)
// lookups.
fn assert_overlap(
    header: &SignedHeader,
    validators: &Vec<Validator>,
    expected: Result<(), &'static str>,
) {
    for lookup in [SignerLookup::Slot, SignerLookup::Address].iter().copied() {
        assert_eq!(
            TmHeaderVerifier::verify_sufficient_validators_overlap(header, validators, lookup),
            expected
        );
    }
}

#[test]
fn valid_stray_votes_do_not_prevent_a_quorum() {
    for stray in stray_blocks() {
        let (header, validators) = signed_commit(vec![
            Some(block_id()),
            Some(block_id()),
            Some(block_id()),
            stray,
        ]);
        assert_overlap(&header, &validators, Ok(()));
    }
}

#[test]
fn only_matching_block_ids_contribute_to_quorum() {
    for stray in stray_blocks() {
        let (header, validators) = signed_commit(vec![
            Some(block_id()),
            Some(block_id()),
            stray.clone(),
            stray,
        ]);
        assert_overlap(&header, &validators, Err("No enough voting power"));
    }
}

#[test]
fn invalid_stray_signature_is_rejected_even_with_a_quorum() {
    let (mut header, validators) = signed_commit(vec![
        Some(block_id()),
        Some(block_id()),
        Some(block_id()),
        None,
    ]);
    header.commit.as_mut().unwrap().signatures[3].signature = vec![0; 64];
    assert_overlap(&header, &validators, Err("Invalid commit signature"));
}
