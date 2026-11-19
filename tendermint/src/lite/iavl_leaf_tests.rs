//! BNB ICS23 v0.1.0 leaf-prefix compatibility (SRC-1715).
use super::{valid_iavl_leaf_prefix, CommitmentProofOp, ProofExecute};
use ics23::{commitment_proof::Proof, iavl_spec, tendermint_spec, CommitmentProof, ExistenceProof};

#[test]
fn leaf_prefix_cases_match_go() {
    // Expectations independently checked with the Go fork's public
    // LeafOp.CheckAgainstSpec(IavlSpec), not a reimplementation of its parser.
    for row in include_str!("testdata/iavl_leaf_prefixes.tsv").lines() {
        let fields: Vec<_> = row.split('\t').collect();
        let prefix = hex::decode(if fields[1] == "-" { "" } else { fields[1] }).unwrap();
        assert_eq!(
            valid_iavl_leaf_prefix(&prefix),
            fields[2] == "true",
            "{}",
            fields[0]
        );
    }
}

#[test]
fn iavl_verification_checks_prefix_before_hashing() {
    let mut leaf = iavl_spec().leaf_spec.unwrap();
    leaf.prefix = vec![0];
    let op = CommitmentProofOp {
        field_type: "ics23:iavl".into(),
        proof: CommitmentProof {
            proof: Some(Proof::Exist(ExistenceProof {
                leaf: Some(leaf),
                // No membership proof is required to reject a malformed leaf op.
                ..Default::default()
            })),
        },
    };
    assert_eq!(
        op.run(Vec::new(), Vec::new()),
        Err("invalid IAVL leaf prefix")
    );
}

#[test]
fn simple_tree_leaf_prefix_is_not_subject_to_iavl_rules() {
    let key = b"store".to_vec();
    let value = b"value".to_vec();
    let leaf = tendermint_spec().leaf_spec.unwrap();
    assert_eq!(leaf.prefix, vec![0]);
    let op = CommitmentProofOp {
        field_type: "ics23:simple".into(),
        proof: CommitmentProof {
            proof: Some(Proof::Exist(ExistenceProof {
                key: key.clone(),
                value: value.clone(),
                leaf: Some(leaf),
                path: Vec::new(),
            })),
        },
    };
    assert!(op.run(value, key).is_ok());
}
