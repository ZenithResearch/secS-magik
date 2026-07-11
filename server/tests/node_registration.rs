use server::manifest::{node_registration_descriptor, ReceiverManifest};
use server::node_registration::{
    NODE_REGISTRATION_HANDLER_ID, NODE_REGISTRATION_OPCODE, NODE_REGISTRATION_OPERATION,
};

#[test]
fn node_registration_descriptor_has_first_class_identity() {
    let descriptor = node_registration_descriptor();
    assert_eq!(descriptor.opcode, NODE_REGISTRATION_OPCODE);
    assert_eq!(descriptor.name.as_str(), NODE_REGISTRATION_OPERATION);
    assert_eq!(descriptor.handler_id, NODE_REGISTRATION_HANDLER_ID);

    let active = ReceiverManifest::default_v0()
        .lookup(NODE_REGISTRATION_OPCODE)
        .expect("registration descriptor must be active");
    assert_eq!(active.name.as_str(), NODE_REGISTRATION_OPERATION);
    assert_eq!(
        active.authorization_fingerprint(),
        descriptor.authorization_fingerprint()
    );
}

#[test]
fn node_registration_identity_is_not_an_operation_alias() {
    let descriptor = node_registration_descriptor();
    for alias in [
        "membership.provision",
        "node.list",
        "node.federate",
        "dregg.authority.finalize",
        "authority.execute",
    ] {
        assert_ne!(descriptor.name.as_str(), alias);
    }
    assert_ne!(
        descriptor.opcode, 0x44,
        "membership opcode is not registration"
    );
}
