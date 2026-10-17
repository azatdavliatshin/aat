# AGENTS.md

Rules for anyone (human or tool) working in this repository.

## Framing

This repository is an independent implementation and formal analysis of
proposed standards. The IETF Internet-Drafts on offline attenuating
delegation chains for AI agents are the object of study, not the source of
this work's ideas; the mechanism is never presented as ours. Drafts in scope:
`draft-niyikiza-oauth-attenuating-agent-tokens-01` (AAT-01) and
`draft-asor-wimse-agent-delegation-chain-02` (asor-02), plus related
individual drafts.

## Layout

- `model/` — ProVerif model of the shared chain structure (parent-hash
  linkage, depth/TTL/capability monotonicity, holder binding), instantiated
  for AAT-01 and asor-02.
- `verifier/` — minimal TypeScript verifier, an executable specification
  for the model, checked against published test vectors. Not a product.
- `report/` — implementation and analysis report (RFC 7942 shape).
- `docs/` — public documentation only.

Work code only in `verifier/` and `model/`; public docs only in `docs/` and
`report/`.

## Technical decisions

- TypeScript: Ed25519 and SHA-256 via `node:crypto`, no runtime
  dependencies; property tests with `fast-check`.
- ProVerif (not Tamarin) for the formal model.

## Commits

- No co-author trailers.
- No personal context in commits, code, or docs.
