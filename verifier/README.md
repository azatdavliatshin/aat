# aat-verifier

A minimal TypeScript verifier for attenuating delegation chains: an
executable specification for the ProVerif model in `../model/`, checked
against published test vectors. It is not a product. It is an independent
implementation of a proposed standard, not the standard's own code.

Profile implemented: `draft-asor-wimse-agent-delegation-chain-02`
(asor-02). The AAT-01 profile (`draft-niyikiza-oauth-attenuating-agent-tokens-01`)
is not implemented yet; `verifyChain(…, "aat-01", …)` throws.

## Run

```
npm install
npm test            # property tests, unit tests, the asor-02 vectors
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

## Profile interface

`walkChain(tokens, profile, options)` takes any object with

- `parse(jws)`: classify one token, or fail as `malformed`-class;
- `declaredParentHash(claims)`: the commitment a token declares;
- `tokenChecks`, `rootChecks`, `linkChecks(parent, child)`, `leafChecks`:
  lists of `{ name, step, seq, run() }`.

The walker adds step 1 (signature, accepted-algorithm list, algorithm
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
