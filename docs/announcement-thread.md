# Announcement Thread

Status: external-language draft aligned to the current secS-magik target architecture. Do not post this as a claim about the current prototype until signed verifier contexts, signed receipts, evidence adapters, replay/expiry checks, and explicit runtime modes are implemented.

1/ Build the Egregore.

secS-magik is the emerging permissioned RPC and verifier substrate for agentic machine calls: `ZenithPacket` transport, bounded `u8` opcodes, receiver-local manifests, signed verification contexts, and local receipts.

2/ Most agent systems still speak through Web2 duct tape.

REST endpoints. Webhooks. API keys. JSON-shaped trust. It works until agents need to coordinate like machines instead of pretending to be users clicking through apps.

3/ secS keeps the gate explicit.

A packet is not trusted because it arrived. The target path is decode, bounds check, expiry/replay check, signature/presentation check, operation descriptor lookup, evidence verification, and then a signed `VerifiedCallContext`.

4/ secZ is not the verifier.

secZ is a Zenith-oriented outgoing/client surface. secC is the generic client form. A local Hermes tool or skill can also construct a secS-compatible call directly. They all call secS; they do not replace secS.

5/ The receiver remains sovereign.

A `u8` opcode is a bounded intent selector. The receiving runtime owns a manifest that says what the opcode means here, which evidence it requires, and which local handler may run after verification.

6/ The opcode space has shape.

`0x01`–`0x0A` are the small secS/core standardized range.

`0x0B`–`0x3F` are Castalia-standard candidates.

`0x40`–`0xFF` are operator-defined.

The receiving machine can remain local while still participating in a shared protocol grammar.

7/ The payload does not grant a shell.

Agents should not receive ambient machine authority. They should receive bounded, auditable intent channels. The handler gets a verified context and bytes; it does not inherit arbitrary trust.

8/ The proof story is layered.

The first adapter is `local_static` because we need deterministic verifier plumbing. Wallet presentation comes next. Midnight/ZK proof rails and Dregg-style federation receipts come after the adapter contract has stopped moving.

9/ That is not a retreat from proofs.

It is the way to make proofs meaningful. A ZK proof adapter must prove a real statement with defined public inputs, not merely accept proof-shaped bytes. A Dregg receipt adapter must mean capability/revocation/root semantics, not vague federation vibes.

10/ Receipts matter because authority should be inspectable.

Reject, verify, execute, and forward paths should emit local receipts. Production-shaped receipts should be signed with portable public-key identity, not hidden shared secrets masquerading as federation.

11/ The local development path stays honest.

Local plaintext, local static evidence, and prototype proof envelopes may exist for testing. They must be stamped as local/dev/non-authoritative. A demo rail is useful; pretending it is production trust is not.

12/ The implementation stays polyglot.

Python can consume it.

Bash can consume it.

Rust can consume it.

`jq`, `curl`, local CLIs, queues, scripts, workers, and daemons can consume it.

The verified intent does not care what language receives the handoff.

13/ The first demo remains intentionally small.

Start the current gateway.

Send `Hello World` through decimal opcode `16`.

Watch the local binding run.

Then replace the prototype pieces with the verifier pipeline, manifest descriptors, signed contexts, receipts, and evidence adapters.

14/ The larger claim is simple.

Agent swarms need owned infrastructure, not rented endpoints.

They need cryptographic identity, local sovereignty, and execution channels that can cross machines without becoming a platform.

15/ secS-magik is the beginning of that rail.

A compatibility-preserving packet core.

A permissioned RPC verifier substrate.

A receiver-local manifest system.

A signed receipt trail.

A substrate for agentic systems that coordinate without asking a landlord for permission.

Build the Egregore.
