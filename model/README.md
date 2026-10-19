# ProVerif model of AAT-01 delegation chains

A symbolic (Dolev–Yao) model, in ProVerif's typed applied pi-calculus, of
the chain verification of `draft-niyikiza-oauth-attenuating-agent-tokens-01`
(AAT-01). The mechanism is the draft's; this is an independent analysis of
it. Section numbers are those of -01.

## Running

ProVerif 2.05 on `PATH`.

```
make -C model            # run every .pv, write out/<name>.txt, check results
make -C model summary    # also write out/SUMMARY.md
make -C model clean
```

`make` fails if a query of a normal model is false or cannot be proved, or
if an `.expectfalse.pv` model has no false query. For `.expectfalse.pv`
models the derivation and the attack trace of each false query go to
`out/<name>.trace.txt`. All four models take about 1.5 minutes on a laptop
(`aat01.pv` about 42 s).

| File | Content |
|---|---|
| `common.pvl` | Types, signatures, hash, thumbprint, bounded naturals, capability sets, events, the §7 Verifier (parameterised by the I5 and I6 checks) |
| `aat01.pvl` | AAT-01 roles: key generation, key compromise, Anchor, Holder |
| `aat01.pv` | AAT-01 with every check; queries P1–P4 |
| `aat01-no-i5.expectfalse.pv` | I5 (`par_hash`) check removed; P1 |
| `aat01-no-i6.expectfalse.pv` | I6 (PoP signature) check removed; P4 |
| `aat01-p4-inj.expectfalse.pv` | every check; P4 as an injective correspondence |

## The model

- **Tokens** are terms `tok(jti, iss, cnf, del_depth, del_max_depth, exp,
  tools, par_hash)` carried as `sign(tok(...), k)`. Signatures are perfect:
  `checksign(sign(m, k), pk(k)) = m`, and anyone can read `m` (`getmess`).
  `h` and `thumb` are free constructors (one-way, collision-free).
  `par_hash` is `h` of the parent *payload* (the JWS signing input), not of
  the signature (B18).
- **Roles.** `KeyGen` creates honest holder keys. `Anchor` mints roots for
  honest holders with a grant the attacker chooses. `Holder` takes any
  signed token from the network that names its key in `cnf` and either
  derives a child for another honest holder (§6, all nine steps) or signs a
  PoP for a tool and arguments the attacker chooses (§5.2). `Compromise`
  hands any honest holder key to the attacker at any time (§8.4); from then
  on the attacker derives and invokes as that holder, also for keys of its
  own. `Verifier` runs §7 on chains of 1 to 4 tokens that the attacker
  assembles freely, and emits `AcceptedRoot` and `AcceptedLink` once steps
  1–5 pass and `Accept` once steps 6–7 pass.
- **Attacker.** Controls the network, sees every token and PoP, makes its
  own keys and names, and learns any honest key it chooses to compromise.
  The trust anchor key is never compromised (§8.3 is out of scope).

### Abstractions and why

| Abstraction | Why |
|---|---|
| `del_depth`, `del_max_depth`, `exp` are naturals bounded by 3 (MAX_DELEGATION_DEPTH = 3; at most 4 tokens) | ProVerif needs a finite verifier: one process per chain length. Depth 3 is enough for a root, two intermediates and a leaf, which is the smallest chain where an intermediate link is neither the root nor the leaf's parent. |
| Tools: subsets of a three-tool alphabet `{ta, tb, tc}`, encoded as `cs(n1, n2, n3)`; subset is pointwise `<=` | Three tools are enough to have a proper subset, a disjoint set and the empty set. |
| I4's argument constraint lattice (§3.4, §4.5) is **not** modelled; `hta` is an opaque term that must equal the invocation's arguments | Subsumption between constraint types is a property of the constraint semantics, not of the chain protocol. It is checked by the TypeScript verifier (`verifier/src/profiles/aat01-constraints.ts`) and by the draft author's own Alloy work. |
| No time: `iat`, `now`, MAX_IAT_SKEW, MAX_TOKEN_LIFETIME, the PoP clock window are absent; only `exp` monotonicity (4h) is checked | The symbolic model has no clock. P3 for expiry is the order `exp(leaf) <= exp(root)`, not freshness. |
| No size limits (2a, 2b), no `alg` checks (3a, 4a, 7a), no constraint depth (3n, 4o) | All are input sanitation; in the symbolic model there is one signature algorithm and terms have no size. |
| No `jti` cycle detection (2c) | A presented chain is linear by the depth checks (4d); no query depends on distinct `jti`s. |
| No `aat_aud` (7d) | Optional, deployment policy. |
| One trust anchor, one issuer URI | See B11 below. |
| Honest holders do not verify the chain above the token they derive from | Gives the attacker more power (honest holders sign children of tokens the attacker made up); the queries still hold. |

### Simplifications forced by ProVerif

- **Built-in `nat` instead of an enumerated `zero/succ/leq` theory.** The
  first version used a `num` type with `zero`, `succ` and `leq`/`subset`
  predicates defined by enumerated clauses over `{0..3}` and three bits.
  ProVerif ran out of memory and was killed (exit 137) on `aat01.pv`, and
  did not finish in 10 minutes with chains limited to 2 tokens: every
  predicate hypothesis is resolved against every fact, and the cases
  multiply across links. ProVerif's built-in `nat` (`0`, `+ 1`, `<=`)
  handles the same comparisons with its own constraint solving. The bound
  is still explicit: the root check and the Anchor require
  `del_max_depth <= 3`, `exp <= 3` and tool entries `<= 1`.
- **P4 is non-injective in `aat01.pv`.** ProVerif cannot model the stateful
  `jti` cache of §5.3/§8.5 (restrictions with time points are not
  accepted, and tables have no atomic "insert if absent"). The §7
  algorithm itself is stateless, so the injective form is false against it;
  that is `aat01-p4-inj.expectfalse.pv`.

## Queries

`HonestKey(k)`: `k` was created by `KeyGen`. `Corrupt(k)`: `k` was handed
to the attacker.

- **P1a** `AcceptedRoot(r) ==> Minted(r)` — every root of a chain that
  passes steps 1–5 was minted by the anchor.
- **P1b** `AcceptedLink(p, c) && HonestKey(cnf(p)) ==> Derived(p, c) ||
  Corrupt(cnf(p))` — every link whose parent names an honest holder key was
  derived from *that* parent by that holder, unless the key was
  compromised. Together with P1a and induction on the chain: every link of
  a chain is signed by the previous holder, up to the first compromised
  key.
- **P2** `Accept(root, leaf, x, …) ==> Granted(root.jti, root.tools) &&
  x ∈ root.tools` — the invoked tool was granted at the root.
- **P3** `Accept(root, leaf, …) ==> leaf.del_depth <= root.del_max_depth &&
  leaf.del_max_depth <= root.del_max_depth && leaf.exp <= root.exp`.
- **P4** `Accept(root, leaf, x, args, pop_jti) && HonestKey(leaf.cnf) ==>
  Invoked(leaf.cnf, leaf.jti, x, args, pop_jti) || Corrupt(leaf.cnf)` — the
  leaf holder signed this invocation. Non-injective (see above).

P2 and P3 hold with no exception for compromised keys: a compromised
holder can sign anything, but the verifier's link checks still bound it.

### Draft section → model construct → query

| Draft | Model construct | Query |
|---|---|---|
| §3.2 claims; §3.7.3 root issuance | `tok(...)`, `Anchor` | P1a |
| §7 step 3 (root) | `check_root` in `common.pvl` | P1a, P3 |
| §4.2 I1, §7 4b–4c | `checksign(s, parent.cnf)`, `iss = thumb(parent.cnf)` in `check_link` | P1b |
| §4.3 I2, §7 4d–4g, 4m | `cd = pd + 1`, `cd <= pm`, `cd <= 3`, `cm <= pm`, `cd <= cm` | P3 |
| §4.4 I3, §7 4h | `ce <= pe` (only) | P3 |
| §4.5 I4, §7 4p1 | pointwise `<=` on `cs(...)` (tool sets only) | P2 |
| §4.6 I5, §7 4q | `cpar = h(parent payload)`, flag `i5` | P1b; `aat01-no-i5` |
| §6 derivation | `Holder`, derive branch | P1b (event `Derived`) |
| §7 step 5 | holds by construction (one process per length) | — |
| §7 step 6b | `has_tool(x, leaf.tools)` | P2 |
| §4.7 I6, §5, §7 7b–7f | `checksign(pop, leaf.cnf)`, `aat_id = leaf.jti`, tool and `hta` equality, flag `i6` | P4; `aat01-no-i6`, `aat01-p4-inj` |
| §8.4 holder key compromise | `Compromise`, event `Corrupt` | P1b, P4 |

### Observations made visible as modelling choices

- **B11 (root `iss` vs anchor key).** The model has one anchor and one
  issuer URI, so `root.iss` is checked against a constant. With several
  anchors the draft does not tie `iss` to the verifying key; the model
  does not explore that.
- **B14 (parse before verify).** Symbolically, claims are matched on the
  output of `checksign`, i.e. verify-then-parse; the draft's ordering is
  respected and the B14 deviation of the TypeScript verifier (parse all,
  then verify) has no symbolic counterpart, since it changes only which
  denial code is reported.
- **B19 (Madden: no PoP on intermediate links; parent validity).** The
  only proof that an intermediate holder took part is its signature on the
  child (I1); P1b is exactly that property. Nothing revokes a parent after
  derivation: an honest holder keeps using its token after deriving from
  it, and the model allows it.
- **B23 (PoP binds the leaf `jti` only).** `popm(pop_jti, aat_id, tool,
  hta)` has no chain or `par_hash` component, and P4 is stated over the
  leaf key and leaf `jti`, not the leaf token. The `aat01-p4-inj` trace
  shows the consequence: one PoP is accepted under two different chains.

## Results

From `out/SUMMARY.md` (ProVerif 2.05):

| Model | Query | Result | Seconds (model) |
|---|---|---|---|
| `aat01` | P1a | true | 42 |
| `aat01` | P1b | true | 42 |
| `aat01` | P2 | true | 42 |
| `aat01` | P3 | true | 42 |
| `aat01` | P4 (non-injective) | true | 42 |
| `aat01-no-i5.expectfalse` | P1a | true | 16 |
| `aat01-no-i5.expectfalse` | P1b | **false** (trace) | 16 |
| `aat01-no-i6.expectfalse` | P4 | **false** (trace) | 12 |
| `aat01-p4-inj.expectfalse` | P4 injective | **false** (trace) | 24 |
| `aat01-p4-inj.expectfalse` | P4 non-injective (printed by ProVerif alongside) | true | 24 |

The model is sensitive to the invariants it is supposed to depend on:
removing I5 breaks P1, removing I6 breaks P4.

### Attack traces

Full derivations and traces: `out/*.trace.txt`.

**No I5 (`aat01-no-i5`).** The anchor mints two roots for the same honest
holder H, and H derives a child from the second one. The attacker presents
that child under the *first* root: the child is signed by H's key and names
H's thumbprint as issuer, so every remaining check passes, and the verifier
accepts a link that H never made (grant-context substitution, §4.6). (The
trace ends at a later link of the same chain built the same way; the first
link already violates P1b.)

**No I6 (`aat01-no-i6`).** Honest holders build a correct three-token
chain for tool `ta`: a root held by H1, a child H1 derived for H2, and a
leaf H2 derived for H3; the attacker reads it off the network.
The attacker writes a PoP for `ta` with the leaf's `jti` and signs it with
a key of its own. A verifier that does not check the PoP signature accepts
the invocation as H3's, although H3 never made it.

**P4 injective (`aat01-p4-inj`).** An honest holder H signs one PoP for
tool `ta` and a leaf `jti` the attacker supplied. The attacker compromises
the holders of two different roots, has each delegate to a key of its own,
and with those keys builds two different chains whose leaves name H's key
and that `jti`. The verifier accepts the one PoP under both chains: §7
alone does not prevent replay, and because the PoP commits only to the
leaf `jti` (B23), the replay need not even reuse the chain.

## What the model does not say

Nothing about constraint semantics (I4 below the tool level), time
(freshness, skew, lifetimes), revocation, the trust anchor's key, size and
algorithm checks, or chains longer than 4 tokens. Results are for the
bounded model above; a `true` is a ProVerif proof for unbounded sessions
of that model, not for the draft text.
