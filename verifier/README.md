# aat-verifier

A minimal TypeScript verifier for attenuating delegation chains: an
executable specification for the ProVerif model in `../model/`, checked
against published test vectors. It is not a product. It is an independent
implementation of a proposed standard, not the standard's own code.

Profiles implemented: `draft-asor-wimse-agent-delegation-chain-02`
(asor-02) and `draft-niyikiza-oauth-attenuating-agent-tokens-01` (AAT-01).

## Run

```
npm install
npm test            # property tests, unit tests, the asor-02 vectors, our AAT-01 vectors
npm run typecheck
```

Node 22 or later. No runtime dependencies: `node:crypto` only.

## Layout

| Path | Role |
|---|---|
| `src/jws.ts` | strict compact JWS parse; EdDSA and HS256 verification |
| `src/json.ts` | strict JSON (duplicates, non-finite, lone surrogates, > 2^53-1) and RFC 8785 JCS |
| `src/hash.ts` | SHA-256 → base64url, JWS signing input, `par_hash` |
| `src/chain.ts` | generic chain walk: shared signature and parent-commitment checks, profile checks run in step order |
| `src/profiles/asor02.ts` | the asor-02 checks, each named and tagged with its draft section |
| `src/profiles/asor02-authority.ts` | scope grammar, constraints, subsumption, action check (§4, §6 step 8) |
| `src/profiles/aat01.ts` | the AAT-01 checks (root, links I1 I2 I3 I4 I5, leaf), each named and tagged with its §7 step |
| `src/profiles/aat01-constraints.ts` | the nine constraint types: value model, check predicate, subsumption (§3.4, §4.5) |
| `src/profiles/aat01-pop.ts` | leaf argument check (step 6b) and PoP JWT (I6, step 7) |
| `src/testing/aat-mint.ts`, `aat-vectors.ts` | test-only minting of chains and PoP; generator of `vectors/aat/` |
| `src/holder.ts` | DPoP holder binding (§6 step 6), EdDSA proofs |
| `src/testing/sign.ts` | signing helpers, test only |

## Using it

```ts
import { verifyChain } from "./src/index.js";

const result = verifyChain(tokens, "asor-02", {
  keys: { "root-1": { alg: "EdDSA", publicKey } },
  now: Math.floor(Date.now() / 1000),
  audience: "https://rp.example",   // omit to verify the chain alone
  request: { dpop, action, totals }, // optional: steps 6 and 8
});
if (!result.ok) console.log(result.code, result.section, result.check, result.message);
```

Failures are values: `{ ok: false, code, section, message, token?, check? }`.
`code` is the outcome name of asor-02 Table 2. The function throws only for
programmer error (empty chain, unimplemented profile). On success,
`stepsPerformed` lists the draft's steps that ran; steps 6 and 8 run only
when the corresponding request input is supplied (§6.1).

## AAT-01

```ts
const result = verifyChain(chain, "aat-01", {
  trustAnchors: [{ alg: "EdDSA", publicKey }],   // bare keys, no kid (§7 inputs)
  now,
  aat: { maxDelegationDepth: 16, maxTokenLifetime: 7 * 24 * 3600, popAudience: "https://tools.example.com" },
  request: { aat: { tool: "read_file", args: { path: "/data/a" }, pop } }, // steps 6 and 7; omit to verify the chain alone
});
```

Failure `code`: `I1`..`I6` (invariants of §4), `signature_invalid`,
`malformed`, `root_invalid`, `jti_cycle`, `size_limit`, `chain_empty`,
`chain_length`, `constraint_depth`, `unknown_constraint`,
`authorization_denied` (step 6). Every PoP failure is `I6`. Steps run in the
draft's order, pair by pair for step 4. Options and defaults: see `AatOptions`
(`MAX_*` values follow the draft's recommendations; `maxDelegationDepth`, which
the draft leaves open, defaults to 16; `rejectSub` defaults to true).

Limits of this implementation: Ed25519 (OKP) keys only, no Ed448 and no EC/RSA;
HS256 is never accepted for AAT; no `jti` replay cache for PoP; extension
constraint types are denied (fail closed). Not following §7 literally: all
tokens are parsed before any signature is verified (every outcome is still a
denial, but the code reported for a forged, malformed token can be `malformed`
rather than `signature_invalid`).

### Constraint types and our subsumption rule

`child ⊑ parent` holds only for the pairs below (§4.5: any pair not named is
rejected). Anything is ⊑ a parent `wildcard`; a derived `wildcard` needs a
`wildcard` parent. "Set" comparisons use JSON equality (RFC 8785 serialisation).

| Type | Check (argument value) | Child ⊑ parent when | Beyond the draft |
|---|---|---|---|
| `exact` | equals `value` | parent `exact`: same value; parent `range`: child value is a number inside it (inclusivity honoured); parent `one_of`: child value is a member | other parent types rejected, including `not_one_of`, `any`, `all` |
| `range` | number within `min`/`max`; both inclusive unless flagged | parent `range`: each child bound present when the parent's is, at least as tight; at an equal bound, child exclusive is fine, child inclusive under a parent exclusive is not | no empty-range handling; `range` under `one_of` rejected |
| `one_of` | member of `values` | parent `one_of`: `values` is a subset | under `range`/`not_one_of` rejected |
| `not_one_of` | not a member of `excluded` | parent `not_one_of`: `excluded` is a superset | against a parent `one_of`: rejected (§4.5 says so) |
| `contains` | array containing every `required` | parent `contains`: `required` is a superset | arrays treated as sets |
| `subset` | array, every element in `allowed` | parent `subset`: `allowed` is a subset | arrays treated as sets |
| `wildcard` | any value | parent `wildcard` only | the argument must still be present (closed world) |
| `all` | every clause holds | parent `all`: each parent clause gets a distinct child clause that is ⊑ it (backtracking one-to-one assignment); extra child clauses allowed | non-`all` child under `all` parent rejected; empty `constraints` malformed |
| `any` | some clause holds | parent `any`: each child clause is ⊑ some parent clause (cross-type clauses allowed per the table) | non-`any` child under `any` parent rejected; empty `constraints` malformed |

Unknown `constraint_type`: denied (`unknown_constraint`). Extra members on a
core type: `malformed`. MAX_CONSTRAINT_DEPTH (32) bounds `all`/`any` nesting.

## Profile interface

`walkChain(tokens, profile, options)` takes any object with

- `parse(jws)`: classify one token, or fail as `malformed`-class;
- `declaredParentHash(claims)`: the commitment a token declares;
- `tokenChecks`, `rootChecks`, `linkChecks(parent, child)`, `leafChecks`:
  lists of `{ name, step, seq, run() }`;
- optionally `preflight(tokens, options)` (size limits before parsing) and
  `sharedChecks(chain, options)`, which replaces the default signature and
  `par_hash` checks when keys are chosen per link (AAT-01: the parent's
  `cnf.jwk`).

Unless the profile replaces them, the walker adds step 1 (signature, accepted-algorithm list, algorithm
configured for the key) and step 2 (constant-time `par_hash` comparison),
sorts every check by `(step, seq)` and returns the first failure. Step 0 is
parse-time classification, before step 1.

## HS256

The asor-02 vectors are signed with a shared HS256 secret, so HS256
verification exists, marked `test-vector support`. It is off by default:
`acceptedAlgs` defaults to `["EdDSA"]`, and a token verifies under HS256 only
if the caller lists `"HS256"` and supplies an HS256 key for the token's
`kid`. Do not use it outside tests.

## Not implemented

- Step 7, status lists: a token carrying a `status` claim is denied with the
  distinct code `not_implemented`; tokens without one pass step 7.
- Step 6 for `x5t#S256` (mTLS) confirmation and for ES256 proofs.
- DPoP `jti` replay cache.
- Cumulative running totals are taken from the caller (`request.totals`).

## Vector provenance

`vectors/asor/` holds the 35 offline-verification vectors for asor-02,
copied byte for byte from the `attenu-guard` 0.20.0 source distribution
(`tests/vectors-02/`), Apache License 2.0; `LICENSE` and `NOTICE` are kept
alongside. Each vector names the outcome it must produce; the test asserts
the outcome and, for rejections, the outcome name.
