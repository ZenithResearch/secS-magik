#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use server::evidence::SecsWalletChallenge;
use wallet_fixtures::{
    wallet_public_key_ref, WALLET_AUDIENCE, WALLET_EXPIRES_AT, WALLET_ISSUED_AT, WALLET_OPERATION,
    WALLET_ORIGIN, WALLET_REPLAY_NONCE_REF, WALLET_RESOURCE, WALLET_SUBJECT,
};

fn wallet_challenge_contract_fixture() -> SecsWalletChallenge {
    SecsWalletChallenge {
        subject: WALLET_SUBJECT.to_string(),
        audience: WALLET_AUDIENCE.to_string(),
        origin: WALLET_ORIGIN.to_string(),
        operation: WALLET_OPERATION.to_string(),
        resource: WALLET_RESOURCE.to_string(),
        nonce: WALLET_REPLAY_NONCE_REF.to_string(),
        issued_at: WALLET_ISSUED_AT,
        expires_at: WALLET_EXPIRES_AT,
        signature_suite: SecsWalletChallenge::ED25519_SIGNATURE_SUITE.to_string(),
        public_key_ref: wallet_public_key_ref(),
    }
}

#[test]
fn wallet_challenge_contract_canonical_bytes_have_exact_layout_and_order() {
    let challenge = wallet_challenge_contract_fixture();

    assert_eq!(
        String::from_utf8(challenge.canonical_bytes()).expect("canonical bytes are UTF-8"),
        format!(
            concat!(
                "secs-wallet-challenge-v1\n",
                "subject:23:did:example:alice#key-1\n",
                "audience:17:secS://local-test\n",
                "origin:25:https://gallery.localhost\n",
                "operation:24:candidate.wallet.present\n",
                "resource:16:application/json\n",
                "nonce:25:nonce:wallet-present-0001\n",
                "issued_at:10:1717000000\n",
                "expires_at:10:1717000300\n",
                "signature_suite:7:Ed25519\n",
                "public_key_ref:{}:{}\n"
            ),
            wallet_public_key_ref().len(),
            wallet_public_key_ref()
        )
    );
}

#[test]
fn wallet_challenge_contract_binds_all_secs_required_fields() {
    let baseline = wallet_challenge_contract_fixture().canonical_bytes();

    let mutations = [
        SecsWalletChallenge {
            subject: "did:example:bob#key-1".to_string(),
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            audience: "secS://other-target".to_string(),
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            origin: "https://evil.example".to_string(),
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            operation: "candidate.wallet.other".to_string(),
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            resource: "application/cbor".to_string(),
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            nonce: "nonce:wallet-present-0002".to_string(),
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            issued_at: WALLET_ISSUED_AT + 1,
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            expires_at: WALLET_EXPIRES_AT + 1,
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            signature_suite: "Ed25519ph".to_string(),
            ..wallet_challenge_contract_fixture()
        },
        SecsWalletChallenge {
            public_key_ref: "pubkey:rotated-fixture".to_string(),
            ..wallet_challenge_contract_fixture()
        },
    ];

    for mutated in mutations {
        assert_ne!(mutated.canonical_bytes(), baseline);
    }
}
