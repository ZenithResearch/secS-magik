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

Three descriptor fixtures, including a 20-operation media-library stress model,
must validate without service-specific validator branches. Twenty-one malformed cases cover delegation, transport/authority confusion,
unsupported selectors, unknown references and duplicate identifiers. Passing
these checks validates proposal documents only. The shared SDK, generated editor,
signature binding, semantic adapters and installed conformance suite still need
implementation and qualification.


The media-library fixture deliberately has overlapping labels (Project) and
non-DevGraph objects (Collection, Asset, RenderJob), as well as creation, moves
and job execution. Passing the fixture validator is vocabulary validation only.
The v1 profile cannot yet encode containment policy, exact-object selectors,
creation destinations or all affected resources. The [roundtable](../../../specs/authorization-resource-model-roundtable.md)
spells out those missing runtime requirements. No working service or generated
editor is created by this example. Supported constraint-profile IDs are checked
against this fixture validator's explicit registry; metadata cannot install one.
