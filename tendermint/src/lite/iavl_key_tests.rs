//! Proof-envelope key binding, compared with Go's two-component KeyPath rules.
use super::{execute, KeyValueMerkleProof, Proof, ProofOp};
use parity_bytes::BytesRef;

fn envelope(store: &[u8], key: &[u8], operator_keys: &[&[u8]]) -> KeyValueMerkleProof {
    KeyValueMerkleProof {
        store_name: store.to_vec(),
        key: key.to_vec(),
        value: vec![1],
        app_hash: vec![0; 32],
        proof: Proof {
            ops: operator_keys
                .iter()
                .enumerate()
                .map(|(index, key)| ProofOp {
                    field_type: if index == 0 {
                        "ics23:iavl"
                    } else {
                        "ics23:simple"
                    }
                    .into(),
                    key: key.to_vec(),
                    // No proof payload is needed to check the envelope binding.
                    data: Vec::new(),
                })
                .collect(),
        },
    }
}

#[test]
fn operator_keys_match_go_path_consumption() {
    // Expected outcomes checked with bnb-chain/tendermint v0.31.17's
    // ProofOperators.Verify and BSC's x:-prefix keyVerifier rule.
    let cases: &[(&str, &[u8], &[u8], &[&[u8]], bool)] = &[
        ("matching", b"store", b"entry", &[b"entry", b"store"], true),
        (
            "wrong leaf",
            b"store",
            b"entry",
            &[b"other", b"store"],
            false,
        ),
        (
            "wrong store",
            b"store",
            b"entry",
            &[b"entry", b"other"],
            false,
        ),
        ("reversed", b"store", b"entry", &[b"store", b"entry"], false),
        ("empty leaf", b"store", b"entry", &[b"", b"store"], false),
        ("empty store", b"store", b"entry", &[b"entry", b""], false),
        ("empty operators", b"store", b"entry", &[b"", b""], false),
        ("empty metadata key", b"store", b"", &[b"", b"store"], false),
        (
            "empty metadata store",
            b"",
            b"entry",
            &[b"entry", b""],
            false,
        ),
        ("missing operator", b"store", b"entry", &[b"entry"], false),
        (
            "extra operator",
            b"store",
            b"entry",
            &[b"entry", b"store", b"extra"],
            false,
        ),
        (
            "escaped bytes",
            b"a/b",
            b"\x00%2F+\xff",
            &[b"\x00%2F+\xff", b"a/b"],
            true,
        ),
        (
            "hex prefix key",
            b"store",
            b"x:6162",
            &[b"x:6162", b"store"],
            false,
        ),
        (
            "hex prefix store",
            b"x:6162",
            b"entry",
            &[b"entry", b"x:6162"],
            false,
        ),
        (
            "literal percent prefix",
            b"store",
            b"x%3A6162",
            &[b"x%3A6162", b"store"],
            true,
        ),
    ];
    for (name, store, key, operator_keys, expected) in cases {
        let proof = envelope(store, key, operator_keys);
        assert_eq!(proof.ics23_keys_match(), *expected, "{}", name);
        if !expected {
            // Rejection must happen before attempting to decode proof payloads.
            assert!(!proof.validate_ics23(), "{}", name);
        }
    }
}

#[test]
fn existing_valid_ics23_fixture_passes_planck_and_plato() {
    // Unmodified positive fixture from reth-bsc's existing Plato precompile test.
    let input = hex::decode(include_str!("testdata/valid_plato_proof.hex").trim()).unwrap();
    for (planck, plato) in [(true, false), (false, true)] {
        let mut output = [0u8; 32];
        assert_eq!(
            execute(
                &input,
                &mut BytesRef::Fixed(&mut output),
                false,
                planck,
                plato
            ),
            Ok(())
        );
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(output, expected);
    }
}
