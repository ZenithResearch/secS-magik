use server::dregg_authority::AuthorityMode;
use server::verifier::VerificationError;
use std::str::FromStr;

#[test]
fn canonical_authority_mode_labels_parse_and_serialize_without_legacy_aliases() {
    let cases = [
        (AuthorityMode::LocalFixture, "local_fixture"),
        (AuthorityMode::SignedSource, "signed_source"),
        (AuthorityMode::SoloVerifiedReceipt, "solo_verified_receipt"),
        (AuthorityMode::FederationCheckpoint, "federation_checkpoint"),
        (AuthorityMode::LightClientVerified, "light_client_verified"),
        (
            AuthorityMode::RecursiveProofCarryingState,
            "recursive_proof_carrying_state",
        ),
    ];

    for (mode, label) in cases {
        assert_eq!(mode.as_str(), label);
        assert_eq!(AuthorityMode::from_str(label), Ok(mode));
    }

    for legacy_or_forbidden in [
        "solo",
        "fixture_snapshot",
        "federation_final",
        "delegated_federated_under_node",
        "bls_threshold_required",
        "rotated_replay_required",
    ] {
        assert_eq!(
            AuthorityMode::from_str(legacy_or_forbidden),
            Err(VerificationError::UnsupportedAuthorityMode),
            "legacy or topology/finality labels must not silently map to canonical authority modes"
        );
    }
}
