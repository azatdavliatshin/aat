---
title: "Independent Implementation and Formal Analysis of Attenuating Delegation Chains for AI Agents"
abbrev: "Attenuation Chains Analysis"
docname: draft-davliatshin-oauth-attenuation-chains-analysis-00
category: info
submissiontype: IETF
ipr: trust200902
area: Security
workgroup: Web Authorization Protocol
keyword: [OAuth, delegation, attenuation, agents, formal verification, interoperability]
venue:
  group: Web Authorization Protocol
  type: Working Group
  mail: oauth@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/oauth/
date: 2026-10-19
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
- ins: A. Davliatshin
  name: Azat Davliatshin
  email: ardavlyatshin@gmail.com
normative:
  RFC7942:
informative:
  RFC7800:
  RFC8259:
  RFC8785:
  RFC9278:
  RFC9396:
  RFC9449:
  RFC9068:
  RFC9421:
  RFC9864:
  AAT-01:
    title: "Attenuating Authorization Tokens for Agentic Delegation Chains"
    target: https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/01/
    seriesinfo:
      Internet-Draft: draft-niyikiza-oauth-attenuating-agent-tokens-01
    author:
    - name: Niki Niyikiza
    date: 2026
  AAT-02:
    title: "Attenuating Authorization Tokens for Agentic Delegation Chains"
    target: https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/
    seriesinfo:
      Internet-Draft: draft-niyikiza-oauth-attenuating-agent-tokens-02
    author:
    - name: Niki Niyikiza
    date: 2026
  ASOR-02:
    title: "Verifiable Attenuated Delegation for AI Agent Chains"
    target: https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/02/
    seriesinfo:
      Internet-Draft: draft-asor-wimse-agent-delegation-chain-02
    author:
    - name: Rafael Asor
    date: 2026
  HAMR-02:
    title: "An Attenuated Delegation Profile for Automated Agents"
    target: https://datatracker.ietf.org/doc/draft-hamr-oauth-agent-delegation/02/
    seriesinfo:
      Internet-Draft: draft-hamr-oauth-agent-delegation-02
    author:
    - name: Amr Hassan
    date: 2026
  COETZEE-03:
    title: "Transaction-Bound Authorization Tokens for Software and AI Agents (SPT-Txn)"
    target: https://datatracker.ietf.org/doc/draft-coetzee-oauth-spt-txn-tokens/03/
    seriesinfo:
      Internet-Draft: draft-coetzee-oauth-spt-txn-tokens-03
    author:
    - name: Rudolf J. Coetzee
    date: 2026
  AGNIHOTRI-02:
    title: "Implementation Status of OAuth Identity Chaining and Transaction Tokens"
    target: https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/02/
    seriesinfo:
      Internet-Draft: draft-agnihotri-oauth-agent-impl-status-02
    date: 2026
  PROVERIF:
    title: "ProVerif: Cryptographic protocol verifier in the formal model"
    target: https://bblanche.gitlabpages.inria.fr/proverif/
    author:
    - name: Bruno Blanchet
  MADDEN-REVIEW:
    title: "Review of the attenuating delegation chain drafts"
    target: https://mailarchive.ietf.org/arch/browse/oauth/
    author:
    - name: Neil Madden
    date: 2026
---

--- abstract

This document reports an independent implementation and formal analysis of
two individual Internet-Drafts that propose offline-verifiable, attenuating
delegation chains for AI agents: Attenuating Authorization Tokens (AATs),
in revisions -01 and -02, and the Agent Delegation Chain of
draft-asor-wimse-agent-delegation-chain-02. It describes a minimal verifier
written from each draft's text, with profiles for AAT -01, AAT -02 and
asor-02, and a ProVerif model of the chain structures of AAT -01 and
asor-02. The AAT -02 profile, written from the text and then run against
the author's 229-vector test suite, agrees with it on all 229 vectors. Of
25 observations recorded on AAT -01, the -02 text resolves 18 (16 closed,
2 closed as intended design); one is partly resolved, one no longer arises,
and five remain open. The report lists ten points where -02 leaves an
implementer more than one conforming behaviour. Two properties raised in
public review are checked on both chain structures. The author of this
report is not an author of either draft. The report specifies nothing; it
follows the shape of RFC 7942.

--- middle

# Introduction

<!-- What goes here: what was done, what was not, who did it. -->

Several individual Internet-Drafts propose chains of signed tokens in which
each link can only narrow the authority of the one before it, so that a
verifier can check an agent's authority offline. This report covers two of
them, {{AAT-01}} with its revision {{AAT-02}}, and {{ASOR-02}}, and
mentions two more, {{HAMR-02}} and {{COETZEE-03}}.

The work began against AAT-01. AAT-02 appeared on 26 October 2026, with
changes that its Appendix F describes as breaking -01 implementations, and
with a byte-exact test-vector suite and a procedure for comparing results.
The verifier gained a separate profile for -02. This report covers both
versions and says which of its observations on -01 the -02 text resolves
({{findings-aat}}).

What was done:

- A minimal TypeScript verifier for the chain checks of both drafts,
  written as an executable specification (see {{verifier}}).
- A separate verifier profile for AAT-02, written from the -02 text and
  then run against the author's 229-vector suite: 229 of 229 verdicts
  agree, with the expected -02 Section 8 step on every denial.
- A ProVerif model {{PROVERIF}} of the shared chain structure (parent-hash
  linkage, depth, lifetime and capability monotonicity, holder binding and
  proof of possession), instantiated for both drafts (see {{model}}).
- This report.

What was not done: no minting or issuing service, no CBOR encoding, no
revocation or status-list handling. The AAT-02 profile was run against the
author's published vectors; it has not exchanged tokens with another running
implementation.

Who did it: an individual, not an author of either draft. The shape and
tone of this report follow {{AGNIHOTRI-02}}. The drafts are
the object of study; the mechanisms described here are theirs.

Source code, model and vectors: [](https://github.com/azatdavliatshin/aat)
(verifier: [](https://github.com/azatdavliatshin/aat/tree/main/verifier);
model: [](https://github.com/azatdavliatshin/aat/tree/main/model)).

# Conventions and Terminology {#conventions}

<!-- What goes here: BCP 14 boilerplate, terms, short names, label scheme. -->

{::boilerplate bcp14-tagged}

This document uses the following terms, informally, across both drafts.

chain:
: An ordered list of tokens, the first a root minted by a trust anchor or
  issuer and each later one a link attenuating its predecessor.

link:
: A token in a chain other than the root.

holder:
: The party named by a token's confirmation claim ({{RFC7800}}) as able to
  use it or derive from it.

issuer:
: The party whose key signs a token.

attenuation:
: Producing a link whose authority (capabilities, depth, lifetime) is no
  greater than its parent's.

PoP:
: Proof of possession of the key a token is bound to, for example a DPoP
  proof {{RFC9449}}.

"AAT-01" is {{AAT-01}}; "AAT-02" is {{AAT-02}}; "asor-02" is {{ASOR-02}}.

Related documents used below: {{RFC8785}} (canonical JSON, used by both
drafts for hashing and comparison), {{RFC9278}} (JWK thumbprint URI) and
{{RFC9396}} (rich authorization requests, the model for structured
authority). TODO(check each against the drafts' own use)

Finding labels A1 to A7 (asor-02), B1 to B25 (AAT-01), C1 to C10 (AAT-02)
and M1, M2 (the two properties of {{model-properties}}) are this document's
own numbering. They
are not used by the drafts or by the reviews cited here.

# Reported Drafts {#drafts}

<!-- What goes here: one subsection per draft; what it proposes, at the
level needed to read sections 4 to 8. No evaluation. -->

## AAT-01 and AAT-02 {#drafts-aat}

{{AAT-01}} (Niyikiza) defines Attenuating Authorization Tokens: JWTs whose
`authorization_details` ({{RFC9396}}) list the tools a holder may invoke and
typed constraints on each argument. A root token is issued by a root issuer
and verified under a configured trust anchor key. Each later token is
derived offline by the holder of its parent: it is signed by the key the
parent names in `cnf.jwk`, its `iss` is that key's JWK thumbprint URI
({{RFC9278}}), and its `par_hash` is the SHA-256 hash of the parent's JWS
signing input (Section 4.6). The invariants I1 to I6 (Section 4) let a
derived token only narrow tools, argument constraints (by a per-type
subsumption relation, Section 4.5), delegation depth and lifetime. At each
tool invocation the leaf holder presents a proof-of-possession (PoP) JWT
over the tool and its arguments (Section 5); an enforcement point checks
the chain and the proof in one algorithm (Section 7).

{{AAT-02}} (26 October 2026) keeps this structure and makes normative
changes that, by its Appendix F, break -01 implementations. The JWS
algorithm is the fully-specified `Ed25519` ({{RFC9864}}) in place of
`EdDSA`, and `typ` is required and explicit (`aat+jwt` for tokens,
`aat-pop+jwt` for the PoP JWT). The PoP JWT carries `aat_hash`, the hash of
the leaf's signing input. Trust anchors are (issuer, public key) pairs, and
the root's `iss` must equal the issuer of the anchor whose key verified it.
Parsing rules are strict: duplicate member names are rejected ({{RFC8259}}),
NumericDates and depths have no fraction or exponent part, `crit` is
processed, and numbers in arguments and constraints must be admissible
(-02 Section 3.4). Constraint maps gain `optional` arguments and a `"*"`
entry for arguments they do not name (-02 Section 3.3). The subsumption
relation is written as a table of valid (parent, derived) pairs, every
other pair invalid (-02 Section 4.5). MAX_DELEGATION_DEPTH is at least 8.
A presentation object with members `aat_chain` and `aat_pop` is defined
(-02 Section 7.4). The verification algorithm is -02 Section 8; this report
names its steps by number and letter (for example, step 3k). -02 publishes
a byte-exact JWS test-vector suite and lists implementations in its
Appendix E. Both versions are implemented; the model is of -01 (see
{{model}}).

## asor-02

{{ASOR-02}} (Asor) defines the Agent Delegation Chain, a profile of OAuth
2.0 JWT access tokens ({{RFC9068}}). Each Delegation Token carries its
authority as `authorization_details` ({{RFC9396}}), the principal in `sub`
(the same value in every token of the chain), the acting agent in
`client_id`, a `del_depth` that grows by one per hop and is bounded by
`del_max_depth`, and, below the root, a `par_hash`: the SHA-256 hash of
the parent's JWS signing input. Tokens are verified under keys configured
at the verifier (Section 6, step 1). The leaf is bound to its holder by
`cnf` ({{RFC7800}}) and a DPoP proof ({{RFC9449}}). The offline
verification algorithm (Section 6) enforces monotonic attenuation, bounded
depth, monotonic expiry and the same principal throughout. Modelled and
implemented.

## hamr-02 and coetzee-03

{{HAMR-02}} (Hassan) builds on HTTP Message Signatures ({{RFC9421}}). An
HTTP header field, `Agent-Delegation`, carries a chain of delegation links,
each of which can only narrow the scope, floors and expiry of the link
before it. Floors cover the person or account behind the agent, answered
by an Attestation Issuer with a signed yes or no, and the class of call the
agent may make (r, w or x, with an optional count per class). The document
defines no credential format: the encoding of each link is that of the
credential format in use (hamr-02 Section 4). Described here, not
implemented or modelled.

{{COETZEE-03}} (Coetzee) defines SPT-Txn, a family of transaction-bound
authorization tokens: a root (CAT), zero or more delegation tokens (CT) and
a per-transaction leaf (TXN), each a signed JWT verified offline under its
issuer's key from a cached trust registry. Each hop narrows scope,
decrements a remaining depth by one and commits to the exact bytes of its
parent by a hash; the leaf is bound to one declared intent, and each
authorization decision emits a signed receipt. The document also specifies
attested issuance through OAuth 2.0 Token Exchange, status-list revocation
and algorithm agility. Described here, not implemented or modelled.

# The Verifier {#verifier}

<!-- What goes here: layout, what is checked, what is not, vectors. Facts
live in verifier/README.md; point at it, do not restate. -->

The verifier is a minimal TypeScript implementation, not a product. It
verifies a chain under one of three profiles, `aat-01`, `aat-02` and
`asor-02`, with a shared chain walk and a profile that supplies the named,
section-tagged checks of the draft. Layout, inputs, failure codes and
options are documented in `verifier/README.md`
([](https://github.com/azatdavliatshin/aat/blob/main/verifier/README.md)).

The `aat-02` profile is a separate set of files that follows -02 Section 8
step by step; every failure carries the step at which it occurs (for
example, `3a` or `4p2`). The `aat-01` profile is kept unchanged next to it,
as the implementation the AAT-01 findings of {{findings-aat}} refer to.

It checks, for asor-02, the steps of its verification procedure up to the
action check; for AAT-01, the root, link and leaf checks of its verification
algorithm and the proof of possession; for AAT-02, every step of -02
Section 8, including the PoP JWT, with PoP `jti` tracking and nonces taken
from state the caller supplies. It does not implement:

- asor-02: status lists (a token carrying a `status` claim is denied with
  the distinct code `not_implemented`), holder binding for `x5t#S256`
  (mTLS) confirmation and for ES256 proofs, or a DPoP `jti` replay cache;
  cumulative running totals are taken from the caller.
- AAT-01: keys other than Ed25519 (OKP), HS256 (never accepted), a PoP
  `jti` replay cache, or extension constraint types (denied); and it parses
  every token before verifying any signature, which is not the order of
  Section 7.
- AAT-02: algorithms other than `Ed25519` (`EdDSA` is denied, -02
  Section 9.11), `cnf.jwk` keys other than OKP Ed25519 (denied at steps 3l
  and 4b2), any `crit` parameter (denied whenever present, since no
  extension parameter is understood), or extension constraint types
  (denied).

The complete list is in `verifier/README.md`.

Vectors:

- asor-02: the 35 offline-verification vectors published with the
  `attenu-guard` 0.20.0 source distribution, Apache License 2.0, copied
  unchanged; all 35 produce the outcome they name.
- AAT-01: 41 vectors of this work's own, written from its reading of -01,
  which publishes none. They are not the author's vectors.
- AAT-02: the author's JWS test-vector suite, 229 vectors (54 permit,
  175 deny), copied byte for byte from [](https://github.com/tenuo-ai/tenuo),
  commit 99fb00994d8d66b213cd12967d6e8eef45025672, file
  `tests/vectors/aat-jws-vectors.json` (SHA-256
  b7a42e9dfdce7fbc1f623670bf060f90e6d6b25f64384cbab1bd79363e82209b),
  Apache License 2.0. Result: 229 of 229 verdicts agree on the first run,
  0 skipped, and the expected -02 Section 8 step on all 175 denials. No
  check was adjusted to a vector. Results were compared with the suite's
  own `compare_results.py`, following its `INTEROP.md`.

# The Model {#model}

<!-- What goes here: abstractions, bound, attacker, properties, results,
limits. Facts live in model/README.md. -->

The model is a symbolic (Dolev-Yao) model in ProVerif's typed applied
pi-calculus. Its roles, abstractions, bound (chains of at most four tokens,
depth and expiry bounded by 3, tool sets over a three-tool alphabet) and
attacker (controls the network, may compromise any holder key, never the
trust anchor's key) are described in `model/README.md`
([](https://github.com/azatdavliatshin/aat/blob/main/model/README.md)).

## Properties {#model-properties}

For both profiles:

P1a:
: Every root of a chain that passes the link checks was minted by the anchor.

P1b:
: Every link whose parent names an honest holder key was derived from that
  parent by that holder, unless the key was compromised. For asor-02, the
  variant P1b' states the same with "some uncompromised configured key"
  in place of the parent's holder (see A7).

P2:
: The invoked tool was granted at the root.

P3:
: Leaf depth, maximum depth and expiry are bounded by the root's.

P4:
: A leaf naming an honest key is used only by that key's holder
  (non-injective).

M1:
: Parent validity after derivation: a parent is still accepted after its
  holder has derived a child from it, with no compromise at all.

M2:
: Intermediate links carry no proof of possession of their own. Variants
  (a) an attacker derives a child of a token it merely observed,
  (b) a request is accepted under such a link, (c) a token is usable
  without its holder's key.

M1 and M2 are the two points of {{MADDEN-REVIEW}}.

## Results {#model-results}

<!-- What goes here: the results table, copied from model/out/SUMMARY.md
(query text abbreviated to its label; full queries are in SUMMARY.md),
ProVerif 2.05, seconds of CPU per model file. -->

| Model | Seconds | Query | Result |
|---|---|---|---|
| aat01 | 63 | P1a | true |
| aat01 | 63 | P1b | true |
| aat01 | 63 | P2 | true |
| aat01 | 63 | P3 | true |
| aat01 | 63 | P4 | true |
| aat01-no-i5 | 22 | P1a | true |
| aat01-no-i5 | 22 | P1b | false |
| aat01-no-i6 | 17 | P4 | false |
| aat01-p4-inj | 34 | P4 injective | false |
| aat01-p4-inj | 34 | P4 | true |
| aat01-m1 | 1 | M1 | reached |
| aat01-m2 | 60 | M2 (a) | true |
| aat01-m2 | 60 | M2 (b) | true |
| aat01-m2 | 60 | M2 (c) = P4 | true |
| asor02 | 245 | P1a | true |
| asor02 | 245 | P1b' | true |
| asor02 | 245 | P2 | true |
| asor02 | 245 | P3 (depth, expiry) | true |
| asor02 | 245 | P3 (maximum depth) | true |
| asor02 | 245 | P4 | true |
| asor02-p1b | 57 | P1b | false |
| asor02-nodpop | 161 | P1a | true |
| asor02-nodpop | 161 | P1b | false |
| asor02-nodpop | 161 | P1b' | true |
| asor02-nodpop | 161 | P2 | true |
| asor02-nodpop | 161 | P3 (depth, expiry) | true |
| asor02-nodpop | 161 | P4 | false |
| asor02-m1 | 208 | M1 | reached |
| asor02-m2 (DPoP on) | 539 | M2 (a) | false |
| asor02-m2 (DPoP on) | 539 | M2 (b) | false |
| asor02-m2 (DPoP on) | 539 | M2 (c) = P4 | true |
| asor02-nodpop-m2 | 175 | M2 (a) | false |
| asor02-nodpop-m2 | 175 | M2 (b) | false |
| asor02-nodpop-m2 | 175 | M2 (c) = P4 | false |
{: #tbl-results title="ProVerif results (version 2.05)"}

A "false" result for a variant model is the expected outcome of that
variant (a check removed, or a property the profile does not claim); each
is accompanied by a ProVerif trace in `model/out/`. TODO(argument: how to
read the table).

## What the Model Does Not Say {#model-limits}

Nothing about constraint semantics below the tool level, time (freshness,
skew, lifetimes; only expiry order), revocation, the trust anchor's key,
size and algorithm checks, or chains longer than four tokens. A "true" is
a ProVerif proof for unbounded sessions of the bounded model, not for the
draft text.

# Findings on AAT-01 {#findings-aat}

<!-- What goes here: one entry per finding, label, section of AAT-01,
argument. Section numbers are those of -01. Kinds: gap, inconsistency,
redundancy, implementation choice. -->

## Constraints (B1 to B8) {#aat-constraints}

- B1 (Section 4.5): cross-type subsumption is an allow-list. TODO(argument)
- B2 (Section 4.5): non-composite child under a composite parent. TODO(argument)
- B3 (Section 4.5): empty composite constraints. TODO(argument)
- B4 (Section 4.5): range corner cases. TODO(argument)
- B5 (Section 3.4): value model and equality. TODO(argument)
- B6 (Section 3.4): arrays as sets. TODO(argument)
- B7 (Section 3.4): unknown members of a core constraint type. TODO(argument)
- B8 (Sections 3.6.2, 4.5): key-set rule and tool omission. TODO(argument)

## Chain (B9 to B19) {#aat-chain}

- B9 (Section 4, Section 7): redundant checks (I2e, step 5). TODO(argument)
- B10 (Section 4.4): MAX_TOKEN_LIFETIME is redundant by construction. TODO(argument)
- B11 (Section 7): which anchor key verifies the root and what `iss` means. TODO(argument)
- B12 (Section 4.2): I1 comparison of a URN as a string. TODO(argument)
- B13 (Sections 3.2, 7, 8.13): algorithms and thumbprints. TODO(argument)
- B14 (Section 7): parse before verify. TODO(argument)
- B15 (Sections 3.2, 3.4): `sub`. TODO(argument)
- B16 (Section 3.2): `jti` format. TODO(argument)
- B17 (Section 7): limits without defaults. TODO(argument)
- B18 (Section 4.6): `par_hash` covers the signing input, not the signature. TODO(argument)
- B19 (Sections 4.2, 8.9): the review's points as AAT-01 answers them. TODO(argument)

## Proof of Possession (B20 to B23) {#aat-pop}

- B20 (Section 5.2): PoP header and `typ`. TODO(argument)
- B21 (Sections 5.2, 7): JCS of the whole PoP payload. TODO(argument)
- B22 (Section 7): clock tolerance. TODO(argument)
- B23 (Section 5): PoP binds the leaf only. TODO(argument)

## Coverage (B24, B25) {#aat-coverage}

- B24 (Section 3.3): empty constraint map and absent arguments. TODO(argument)
- B25: no published test vectors; the 41 vectors are ours. TODO(argument)

# Findings on asor-02 {#findings-asor}

<!-- What goes here: A1 to A7, section of asor-02, argument. -->

- A1 (Section 6, step 1): which key verifies a link below the root. TODO(argument)
- A2 (Section 3, Section 4.3): `del_max_depth` inheritance. TODO(argument)
- A3 (Section 3, Section 6): root without principal, `malformed` or step 3. TODO(argument)
- A4 (Section 6, step 3): chain length bound by convention. TODO(argument)
- A5: coverage of the 35 vectors. TODO(argument)
- A6 (Sections 4.3, 6): a child's `del_max_depth` has no effect. TODO(argument)
- A7 (Sections 6.1, 9.4): who mints a link below the root. TODO(argument)

# Cross-Draft Observations {#cross}

<!-- What goes here: holder-derived versus issuer-minted; the M1/M2 table,
one line per cell. -->

AAT-01 is holder-derived: each link is signed by the key of the previous
holder. asor-02 is issuer-minted (A7): each link is signed by an issuer
key, and the previous holder is bound by `cnf` but takes no part in signing.
TODO(argument)

| Profile | M1 | M2 (a) | M2 (b) | M2 (c) |
|---|---|---|---|---|
| AAT-01 | parent accepted after derivation: yes | no | no | no |
| asor-02, DPoP on | yes | yes: one configured key extends any chain | yes: attacker's own key in the forged leaf's `cnf` | no: DPoP gives P4 |
| asor-02, DPoP off | yes | yes | yes | yes: an observed chain is accepted from anyone |
{: #tbl-madden title="M1 and M2 on both profiles"}

# Implementation Status {#impl-status}

<!-- RFC 7942 Section 2 template; to be removed before publication. -->

Note to the RFC Editor: please remove this section and the reference to
{{RFC7942}} before publication.

This section records the status of known implementations at the time of
posting, following {{RFC7942}}. The inclusion of an implementation here
does not imply endorsement by the IETF.

{{AAT-02}} Appendix E lists further implementations of AATs, and the
`INTEROP.md` file of the author's vector suite keeps a table of results
against it; this report does not restate them.

## aat {#impl-aat}

Organization:
: None (individual).

Name:
: aat (verifier and model).

Description:
: A minimal TypeScript verifier for AAT-01, AAT-02 and asor-02 chains, and
  a ProVerif model of AAT-01 and asor-02; see {{verifier}} and {{model}}.

Level of maturity:
: Research prototype; an executable specification, not a product.

Coverage:
: Chain verification only; no minting service, no CBOR, no revocation.
  asor-02: the token format (Section 3), authority and subsumption
  (Section 4), chain linkage (Section 5) and the offline verification
  algorithm (Section 6) through the action check (step 8), with DPoP
  holder binding (Section 7) for EdDSA proofs; not status lists (step 7,
  Section 8), mTLS confirmation or ES256 proofs. AAT-01: the root, link
  and leaf checks of Section 7 (invariants I1 to I6 of Section 4), the nine
  constraint types and their subsumption (Sections 3.4 and 4.5) and the
  PoP JWT (Section 5); not root issuance (Section 3.7) or derivation
  (Section 6) beyond test-only minting, keys other than Ed25519, or a PoP
  replay cache. AAT-02: every step of -02 Section 8, with the constraint
  map, well-formedness and subsumption rules of -02 Sections 3.3, 3.4 and
  4.5 and the PoP JWT of -02 Section 7; not issuance or derivation (-02
  Section 6), algorithms other than Ed25519, or extension constraint types
  (-02 Section 5).

Version compatibility:
: draft-niyikiza-oauth-attenuating-agent-tokens-01,
  draft-niyikiza-oauth-attenuating-agent-tokens-02 and
  draft-asor-wimse-agent-delegation-chain-02.

Licensing:
: Apache License 2.0.

Implementation experience:
: The AAT-02 profile was written from the -02 text and then run against the
  author's vector suite; it agreed on all 229 vectors on the first run.
  TODO(argument: summary of sections 6 and 7)

Contact:
: Azat Davliatshin, ardavlyatshin@gmail.com

Information date:
: TODO(date of posting)

# Security Considerations

This document specifies no protocol and no change to one. The model's
attacker controls the network, observes every token, and may compromise
any holder key at any time but not the trust anchor's key; results are
only as strong as that attacker and the bounds of {{model-limits}}.

# IANA Considerations

This document has no IANA actions.

--- back

# How to Reproduce {#reproduce}

<!-- What goes here: commands and versions. -->

From the root of [](https://github.com/azatdavliatshin/aat):

- `npm --prefix verifier install`
- `npm --prefix verifier test`: property and unit tests, the 35 asor-02
  vectors, the 41 AAT-01 vectors and the 229-vector AAT-02 suite.
- `npm --prefix verifier run suite:aat02`: runs the AAT-02 suite alone and
  writes `verifier/results/aat02-results.json` in the format of the
  suite's `compare_results.py`.
- In a checkout of the suite's repository:
  `python3 ietf/vectors/compare_results.py results.json`, with
  `results.json` the file written by the previous command. It prints the
  suite's SHA-256 and the count of agreements.
- `make -C model summary`: every ProVerif model, and `model/out/SUMMARY.md`.

Versions: Node 22 or later and ProVerif 2.05 are required. The verifier run
reported here used Node v26.12.0 and npm 11.20.0 (146 tests, 146 passed).
The model results of {{tbl-results}} are from ProVerif 2.05.

# Change Log {#changelog}

<!-- Remove before publication. -->

## -00

Written against AAT-01 and asor-02; extended for AAT-02 after 26 October
2026 with the `aat-02` verifier profile and the result of the author's
vector suite.

# Acknowledgements
{:numbered="false"}

TODO(acknowledgements)
