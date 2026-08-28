# secS-magik ideas

This directory holds exploratory proposals that are worth preserving before they become accepted specifications or implementation plans.

Ideas are **not architecture authority**. They do not supersede [implementation-status.md](../implementation-status.md), [specs/](../specs/), accepted plans, GitHub issues, or tested runtime behavior.

## Status vocabulary

| Status | Meaning |
|---|---|
| Idea | Early proposal; useful enough to record, with no implementation authority. |
| Design-gated | Open conflicts, ownership, security, privacy, or contract decisions block implementation. |
| Promoted | Accepted direction moved into a spec and implementation plan; the idea note links to them. |
| Rejected | Considered and declined; retained with the reason. |
| Superseded | Replaced by another proposal/spec; retained as provenance. |

Every idea note should state:

- its status and tracking issue;
- the problem and proposed seam;
- current architecture conflicts;
- security, privacy, compatibility, and non-claim boundaries;
- the decision gates required before promotion;
- links to any promoted spec, plan, or superseding proposal.

## Current ideas

| Idea | Status | Tracking |
|---|---|---|
| [Optional inference weave middleware](optional-inference-weave-middleware.md) | Design-gated | [#274](https://github.com/ZenithResearch/secS-magik/issues/274) |

## Publication

These files use portable Markdown and relative links and are published with the rest of `docs/` on the repository's GitHub Pages site. Publication is presentation only: it does not promote an idea, resolve its design gates, or grant runtime implementation authority.
