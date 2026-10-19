# ProVerif model of AAT-01 and asor-02 delegation chains

A symbolic (Dolev–Yao) model, in ProVerif's typed applied pi-calculus, of
the chain verification of `draft-niyikiza-oauth-attenuating-agent-tokens-01`
(AAT-01) and `draft-asor-wimse-agent-delegation-chain-02` (asor-02). The
mechanisms are the drafts'; this is an independent analysis of them.
Section numbers are those of -01 unless a section says otherwise; the
asor-02 sections use that draft's numbering.

## Running

ProVerif 2.05 on `PATH`.

```
make -C model            # run every .pv, write out/<name>.txt, check results
make -C model summary    # also write out/SUMMARY.md
make -C model clean
```

`make` fails if a query of a normal model is false or cannot be proved, if
an `.expectfalse.pv` model has no false query, or if an event of a
`.reachable.pv` model (reachability query `query event(E)`) is not
reached. For `.expectfalse.pv` and `.reachable.pv` models the derivation
and the trace of each false query (for reachability: of each reached
event) go to `out/<name>.trace.txt`. Model names are
`<profile>[-variant][.expectfalse|.reachable].pv`; each runs with
`common.pvl` and `<profile>.pvl`. The whole set takes about 25 minutes of
CPU (about 9 minutes with `make -j6`); the slowest file is
`asor02-m2.expectfalse.pv` (about 9 minutes).

| File | Content |
|---|---|
| `common.pvl` | Types, signatures, hash, thumbprint, bounded naturals, capability sets, events, honest key generation and key compromise (both profiles), the AAT-01 §7 Verifier (parameterised by the I5 and I6 checks) |
| `aat01.pvl` | AAT-01 roles: Anchor, Holder |
| `aat01.pv` | AAT-01 with every check; queries P1–P4 |
| `aat01-no-i5.expectfalse.pv` | I5 (`par_hash`) check removed; P1 |
| `aat01-no-i6.expectfalse.pv` | I6 (PoP signature) check removed; P4 |
| `aat01-p4-inj.expectfalse.pv` | every check; P4 as an injective correspondence |
| `aat01-m1.reachable.pv` | Madden M1: parent accepted after derivation (no compromise) |
| `aat01-m2.pv` | Madden M2 (a), (b), (c) |
| `asor02.pvl` | asor-02 token, roles (Anchor, Holder) and §6 Verifier with flag `dpop` |
| `asor02.pv` | asor-02, DPoP on; P1a, P1b′, P2, P3, P4 |
| `asor02-p1b.expectfalse.pv` | asor-02, DPoP on; P1b as for AAT-01 (A1) |
| `asor02-nodpop.expectfalse.pv` | asor-02, step 6 not performed; P1a, P1b, P1b′, P2, P3, P4 |
| `asor02-m1.reachable.pv` | Madden M1 for asor-02 (DPoP on, no compromise) |
| `asor02-m2.expectfalse.pv` | Madden M2 for asor-02, DPoP on |
| `asor02-nodpop-m2.expectfalse.pv` | Madden M2 for asor-02, DPoP off |

## The AAT-01 model

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

## The asor-02 model

`asor02.pvl` encodes §3–§7 of asor-02 as the draft states them, on the
same theory (`common.pvl`: keys, compromise, signatures, `h`, tool sets,
events). Step numbers are those of asor-02 §6.

- **Tokens** are `dt(jti, iss, cnf, del_depth, del_max_depth, exp, tools,
  par_hash)` carried as `sign(dt(...), k)`. `del_max_depth` is `md(n)` or
  absent (`nomd`): §3 requires it in DT_0 only. `par_hash` is `h` of the
  parent payload (the JWS signing input, §3).
- **Step 1 and A1.** DT_0 must verify under the anchor key. For DT_i,
  i > 0, the draft names no key (A1). The Verifier takes a key from the
  attacker (the JWS `kid`) and accepts DT_i if that key is one it is
  configured with — here, any honest holder key — and the signature
  verifies. It does not compare that key with DT_{i-1}.`cnf`: §6 does not
  ask for it, and neither does the TypeScript verifier's reading
  (`verifier/src/profiles/asor02.ts`).
- **Steps 2–5.** `par_hash = h(parent)`; `del_depth = i`; `n <
  DT_0.del_max_depth`; tool sets narrow (rule 1, tool level only); a
  stated child `del_max_depth` is positive (§3) and at most the nearest
  stated ancestor's (rule 5, A2 as the TypeScript verifier reads it);
  `exp` non-increasing (rule 4). No clock.
- **Step 6 (holder binding, §7)** under the flag `dpop`. On: a DPoP proof
  `sign(popm(proof_jti, ath, tool, args), sk)` must verify under
  DT_n.`cnf`, with `ath = h(DT_n as presented)` (RFC 9449 `ath`) and the
  request's tool and arguments (`htm`/`htu` abstracted). Off: §6.1's
  verifier that has not performed step 6; `Accept` carries the constant
  `nodpop`. §6 makes step 6 a MUST for an Enforcement Point; §6.1 and
  §7 describe verifiers that cannot perform it.
- **Step 8** at tool level: the tool is in DT_n's tool set.
- **Roles.** `AnchorAsor` mints DT_0 for an honest holder with
  `del_max_depth` in 1..4 (so chains of at most 4 tokens, as for AAT-01).
  `HolderAsor` takes any token naming its key in `cnf` and either signs a
  child for another honest holder with its own key, or sends a DPoP proof
  for a tool and arguments the attacker chooses. **Who mints DT_i (A7).**
  A DT is an RFC 9068 access token with `iss` (§2); §6.1 speaks of "an
  issuer validating a parent before minting a child" and §9.4 of "two
  issuers". The model reads asor-02 as *issuer-minted*: DT_i (i > 0) is
  signed by an issuer holding one of the verifier's configured keys, and
  the holder of DT_{i-1} is bound by `cnf` but takes no part in signing
  DT_i. The `keys` table is the set of issuer keys, and "an honest holder
  signs the child with its own key" in `asor02.pvl` is read as "an honest
  issuer signs the child with its key". P1b′ is the property asor-02
  intends; P1b (the parent's holder made the link) is one it does not
  claim.
- **Not modelled:** `sub` invariance and `client_id` (strings compared for
  equality; no query depends on them), `aud`, `nbf`/`now`, status lists
  (step 7), constraint types and cumulative constraints (step 8),
  JCS and `alg` checks, more than one trust anchor (§6.4).

### Queries (asor-02)

P1a, P2, P3 and P4 are the AAT-01 queries over `dt(...)`. P3 is stated as
asor-02 bounds depth: `leaf.del_depth < root.del_max_depth`, `leaf.exp <=
root.exp`, and a `del_max_depth` the leaf states is at most the root's. P1b
is stated twice:

- **P1b** (as for AAT-01) `AcceptedLink(p, c) && HonestKey(cnf(p)) ==>
  Derived(p, c) || Corrupt(cnf(p))`: the link was made by the holder of
  the parent. asor-02 does not claim it (A7); it is stated to compare with
  AAT-01.
- **P1b′** `AcceptedLinkBy(k, p, c) && HonestKey(k) ==> Derived(p, c) ||
  Corrupt(k)`, where `k` is the key the verifier used for `c`: the link was
  made, from exactly that parent, by an issuer holding *some* configured key
  that is not compromised.

| Draft (asor-02) | Model construct | Query |
|---|---|---|
| §3 claims; DT_0 under trusted root key (step 1) | `dt(...)`, `AnchorAsor`, `check_root_asor` | P1a |
| Step 1 for DT_i, i > 0 (no key named; A1) | `get keys(=k_i, _)`, `checksign(s_i, k_i)` | P1b, P1b′ |
| §5, step 2 `par_hash` | `cpar = h(parent payload)` | P1b′ |
| Step 3 depth | `cd = pd + 1`; `n < m` per chain length | P3 |
| §4.3 rule 1, step 4 | pointwise `<=` on `cs(...)` (tool sets only) | P2 |
| §4.3 rule 5, step 4; §3 (A2) | `md(cm)`: `1 <= cm <= ` nearest stated bound | P3 |
| §4.3 rule 4, step 5 | `ce <= pe` | P3 |
| §7, step 6 | `checksign(pop, leaf.cnf)`, `ath = h(leaf)`, flag `dpop` | P4; `asor02-nodpop` |
| Step 8 (scope) | `has_tool(x, leaf.tools)` | P2 |

## Results

From `out/SUMMARY.md` (ProVerif 2.05). Seconds are per model file
(`make -j6`, so files ran concurrently); per-query times are in the status
notes, not here.

| Model | Query | Result | Seconds (model) |
|---|---|---|---|
| `aat01` | P1a | true | 63 |
| `aat01` | P1b | true | 63 |
| `aat01` | P2 | true | 63 |
| `aat01` | P3 | true | 63 |
| `aat01` | P4 (non-injective) | true | 63 |
| `aat01-no-i5.expectfalse` | P1a | true | 22 |
| `aat01-no-i5.expectfalse` | P1b | **false** (trace) | 22 |
| `aat01-no-i6.expectfalse` | P4 | **false** (trace) | 17 |
| `aat01-p4-inj.expectfalse` | P4 injective | **false** (trace) | 34 |
| `aat01-p4-inj.expectfalse` | P4 non-injective (printed by ProVerif alongside) | true | 34 |
| `asor02` (DPoP on) | P1a | true | 245 |
| `asor02` | P1b′ | true | 245 |
| `asor02` | P2 | true | 245 |
| `asor02` | P3 (depth, exp) | true | 245 |
| `asor02` | P3 (rule 5) | true | 245 |
| `asor02` | P4 (non-injective) | true | 245 |
| `asor02-p1b.expectfalse` (DPoP on) | P1b | **false** (trace) | 57 |
| `asor02-nodpop.expectfalse` | P1a | true | 161 |
| `asor02-nodpop.expectfalse` | P1b | **false** (trace) | 161 |
| `asor02-nodpop.expectfalse` | P1b′ | true | 161 |
| `asor02-nodpop.expectfalse` | P2 | true | 161 |
| `asor02-nodpop.expectfalse` | P3 (depth, exp) | true | 161 |
| `asor02-nodpop.expectfalse` | P4 | **false** (trace) | 161 |

The Madden files (`*-m1.reachable`, `*-m2*`) are in "Madden properties"
below.

The AAT-01 model is sensitive to the invariants it is supposed to depend
on: removing I5 breaks P1, removing I6 breaks P4. For asor-02, P1b is
false with and without DPoP, and P1b′ is true with and without it: the
draft's step 1 guarantees that each link was signed by *a* configured
(issuer) key, not by the holder of the parent (A1, A7). P1b's failure is a
difference from AAT-01, not a defect of asor-02. DPoP decides only P4.

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

**asor-02 P1b, DPoP on (`asor02-p1b`) and off (`asor02-nodpop`).** The
anchor mints DT_0 for an honest holder H0; the attacker compromises an
unrelated honest holder X. With X's key it signs a DT_1 that commits to
DT_0 (`par_hash`), names an honest holder H1 and narrows correctly; the
verifier, given X's `kid`, accepts the link although H0, the holder of
DT_0, took no part in it. An honest issuer then signs DT_2 for H2 from
that DT_1, and the attacker again signs DT_3 below DT_2 with X's key. Both
traces are the same chain: the link checks are passed by any configured
key, and H0 and H2 are never compromised.

**asor-02 P4, DPoP off (`asor02-nodpop`).** Honest holders build a
three-token chain for tool `ta` (H0 → H1 → H2). The attacker reads it off
the network and presents it with a tool and arguments of its choice and no
proof; a verifier that does not perform step 6 accepts the request as
H2's.

The `asor02-p1b` trace also shows a rule-5 effect: DT_1 states
`del_max_depth` 1, yet DT_2 and DT_3 below it are accepted, because step 3
compares the chain length with DT_0's `del_max_depth` only; rule 5 only
forbids a child from raising the value (A6: a child's `del_max_depth` has
no effect on chain length; in AAT-01 I3 the value binds).

## Madden properties

The two points of Neil Madden's critique of chained attenuating tokens, as
queries on both profiles. Setting for M2: every token an honest party
creates is sent on the public channel (the Anchor and Holder `out` each
signed token, as tokens travel with requests), so the attacker "learns a
mid-chain token T" for every T. It does not get T's holder key; it may
compromise any *other* holder (`Compromise`).

**M1, parent validity after derivation** (`*-m1.reachable.pv`). Event
`AcceptParentAfterDerive(P, C)` is emitted after `Accept` with leaf P if
the holder of P had already derived C from P (private table `derived`,
written by the holder, read by the verifier). Reachability query; the
models have no `Compromise` process, so a reached event is a run of honest
roles only.

| Profile | M1 reached? | Seconds (model) |
|---|---|---|
| AAT-01 | yes (trace) | 1 |
| asor-02 (DPoP on) | yes (trace) | 208 |

This is a property of both designs, not a defect: neither re-keys the
parent or revokes it on derivation (AAT-01 §8.9 defers revocation;
asor-02 §9.1 states it and points to short TTLs and status lists).

**M2, intermediate links without PoP** (`*-m2*.pv`). For a T whose holder
is honest and not compromised:
(a) *derive* — an accepted link below T that T's holder did not make
(P1b);
(b) *leaf accepted* — an accepted request (after step 6 / §7 step 7)
whose chain passes through such a link (`AcceptVia`);
(c) *PoP-bound* — an accepted request with T, or any leaf, that its
holder did not make (P4).

| Profile | (a) attacker derives a child of T | (b) leaf under T accepted | (c) T usable without its key |
|---|---|---|---|
| AAT-01 | no (P1b true) | no (true) | no (P4 true) |
| asor-02, DPoP on | **yes** (false, trace) | **yes** (false, trace) | no (P4 true) |
| asor-02, DPoP off | **yes** (false, trace) | **yes** (false, trace) | **yes** (false, trace) |

Seconds (model): `aat01-m2` 60, `asor02-m2.expectfalse` 539,
`asor02-nodpop-m2.expectfalse` 175.

Trace summaries (`out/*.trace.txt`):

- **M1, AAT-01.** The anchor mints a root for H1; H1 derives a child for
  H2; H2 derives a child of its token for H3 and then signs a PoP for `ta`
  with its own token. The verifier accepts the two-token chain ending in
  H2's token, after H2 derived from it.
- **M1, asor-02.** The same run on a longer chain: H0 → H1 → H2 by honest
  derivation, H2 derives for H3, then presents its own DT_2 with a DPoP
  proof. The verifier accepts DT_2 as the leaf.
- **M2 (a), asor-02, both variants.** As the P1b trace above: with the key
  of an unrelated compromised holder X the attacker signs a child of a
  token held by an honest H, and the verifier accepts the link.
- **M2 (b), asor-02, DPoP on.** As (a), but the forged leaf below the
  honest chain names in `cnf` a key the attacker made itself, and the
  attacker presents it with a DPoP proof under that key. Step 6 checks
  exactly that key, so the request is accepted under a chain whose upper
  links are honest. DPoP binds the presenter of the leaf, not the deriver of each link;
  with any one configured key compromised — it need not belong to the
  chain — the attacker extends an honest chain to a leaf bound to its own
  key and is accepted. The prediction that DPoP stops (b) does not hold.
- **M2 (b), asor-02, DPoP off.** The same forged chain, presented without
  a proof.
- **M2 (c), asor-02, DPoP off.** As the P4 trace above: an honest chain
  presented by the attacker without a proof.

## AAT-01 vs asor-02

The queries show the following and nothing more. Both profiles bound the
leaf by the root on tools, depth and expiry (P2, P3), and both accept a
parent after its holder has derived from it (M1). AAT-01 is
holder-derived (I1): every accepted link below an honest, uncompromised
holder's token was made by that holder (P1b), and no request is accepted
under a link it did not make (M2 b). asor-02 is issuer-minted (A7): an
accepted link was signed by an issuer holding *some* configured,
uncompromised key (P1b′), not necessarily by the holder of the parent
(P1b false; a difference, not a defect). The security of an asor-02 chain
is that of its weakest configured issuer key: one compromised configured
key lets the attacker extend any chain, and with its own key in the leaf
`cnf` have the request accepted even with DPoP (M2 b). DPoP in asor-02
gives exactly P4: a leaf naming an honest key is used only by that key's
holder. It binds the presenter of the leaf, not the deriver of each link.

## What the model does not say

Nothing about constraint semantics (I4 below the tool level; asor-02
constraint types), time (freshness, skew, lifetimes), revocation (asor-02
step 7), the trust anchor's key, size and algorithm checks, asor-02's
`sub`, `client_id` and `aud`, or chains longer than 4 tokens. Results are for the
bounded model above; a `true` is a ProVerif proof for unbounded sessions
of that model, not for the draft text.
