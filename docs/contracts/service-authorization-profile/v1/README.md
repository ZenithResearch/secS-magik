# Proposed service authorization profile

These are review fixtures for the [reusable service specification](../../../specs/reusable-service-authorization-profile-v1.md).
They do not register a service, issue a grant, install a handler or configure a
production verifier. The DevGraph example illustrates a subset of permissions;
it does not replace the complete existing Work/Arena policy.

Run the closed JSON Schema and reference/duplicate checks:

```sh
uv run --no-project --with jsonschema==4.23.0 python \
  docs/contracts/service-authorization-profile/v1/validate.py
```

Two unrelated resource models must validate without service-specific validator
branches. Twelve malformed cases cover delegation, transport/authority confusion,
unsupported selectors, unknown references and duplicate identifiers. Passing
these checks validates proposal documents only. The shared SDK, generated editor,
signature binding, semantic adapters and installed conformance suite still need
implementation and qualification.
