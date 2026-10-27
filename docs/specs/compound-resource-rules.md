# Compound resource rule checks

Status: **implemented Rust resource-only prerequisite**, not a signed permission
format, installed operation adapter or mutation/transaction implementation.
This extends the [selector primitive](resource-selector-v1.md) and the
[compound-operation review](exact-selection-and-compound-operations-roundtable.md).

`compound_resources` provides typed in-process records (no serde/wire schema):

- EffectContract: installed provider operation, canonical service and complete
  effect-role definitions, permitted kinds and bounded cardinality.
- EffectRule: one correlated selection for every declared role.
- ResolvedRole: actual provider-resolved resources in one consistent snapshot.

For a move, roles may include subject, actual source and requested destination,
plus all affected descendants/ACL/quota/ownership resources defined by the
operation. Attach is not arbitrary create; detach is not arbitrary delete. The
provider defines exact operation semantics and resolves the actual source. A
caller cannot supply a trusted effect contract, policy list or ancestry snapshot.

`matching_rule` returns a temporary index only when ONE complete rule covers ALL
resources of ALL required roles. A→B plus C→D therefore does not permit A→D.
`EffectRule::within` compares every child role with that same parent's selector;
no pooling across parent rules. Omitted, duplicate, unknown, wrong-kind and
under/over-cardinality effects fail closed. Contract roles are bounded (16 roles,
16 kinds each, 128 targets per role) with at least one mandatory resource; rule
lists are bounded at 64. The standalone selector's bounds continue to apply.

The index is not a signed permit, durable ID or current-policy proof. Provider
code must retain the exact immutable rule and fence its policy/revocation and
resource versions within the mutation transaction. Check preconditions, mutate,
then recheck that SAME rule with `EffectRule::permits` and enforce postconditions
before commit; roll back on a denial/error. Independently running matching_rule
again after mutation could pick a different rule and is not a valid postcheck.

This library neither takes a database lock nor proves the resolver's state. It
does not consume replay, verify credentials, check holder/installation/validity
or execute an operation. Those remain mandatory gates in the receiver adapter.
Revocation/freshness changes and ambiguous relationships must be handled under
that provider consistency boundary. Cross-service mutations are unsupported.

Wallet Core reuses the same types and complete-rule narrowing function for
public review. No new signing command, custody field, backup decoder or browser
method is added. Existing v1 grants/credentials/opaque conditions and Packet
bytes remain unchanged; the new typed rules cannot be inserted into them.
Provider execution adapters and a separately versioned signed permission
integration remain follow-up work, before any generic editor/issuance rollout.

Tests exercise complete pair acceptance, cross-pair/reverse denial, retained-rule
postchecks, missing/duplicate/unlisted effects, bounded contracts, every target
in multi-resource roles, foreign operation/service/kind and deleted resources.
