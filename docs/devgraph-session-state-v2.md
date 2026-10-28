# DevGraph session work state v2

Source candidate; not an installed grant or deployment claim.

`devgraph.work.session.state.v2` reuses the signed Work v2 transport for a closed
provenance operation. Its only subject kind is `SessionRef`, with an exact `sr-`
plus 64 lowercase hex digest ID and positive expected state revision. The payload
is exactly `{"state":"open"}` or `{"state":"done"}`. Only that SessionRef resource
is admitted. Other Work operations cannot accept a SessionRef subject, and v1
cannot accept this operation. Existing attachment and Work grants gain nothing.

DevGraph owns state, revision checks, receipt commit and the independent
SessionWorkState record. secS normalizes bytes and checks exact current authority;
it does not infer completion from retained native conversations or a tool exit.
Wallet's existing generic credential interface is unchanged. Python/Rust shared
vectors verify canonical bytes, request digest and the exact resource inventory.
