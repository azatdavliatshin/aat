# aat

Independent implementation and formal analysis of proposed standards: IETF
Internet-Drafts on offline attenuating delegation chains for AI agents
(`draft-niyikiza-oauth-attenuating-agent-tokens-01`,
`draft-asor-wimse-agent-delegation-chain-02`). The drafts are the object of
study.

Contents:

- `model/` — ProVerif model of the delegation-chain structure
- `verifier/` — minimal TypeScript verifier (executable specification)
- `report/` — implementation and analysis report

Status: work in progress toward IETF 127.

## Usage

```
npm --prefix verifier install
npm --prefix verifier test
make -C model summary   # ProVerif models, see model/README.md
```

## Licence

Apache-2.0, see `LICENSE`.
