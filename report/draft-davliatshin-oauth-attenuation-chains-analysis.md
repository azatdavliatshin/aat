---
title: "Independent Implementation and Formal Analysis of Attenuating Delegation Chains for AI Agents"
abbrev: "Attenuation Chains Analysis"
docname: draft-davliatshin-oauth-attenuation-chains-analysis-00
category: info
submissiontype: IETF
ipr: trust200902
area: Security
workgroup: Web Authorization Protocol
keyword: [OAuth, delegation, attenuation, agents, formal verification]
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
  RFC8785:
  RFC9278:
  RFC9396:
  RFC9449:
  RFC9068:
  AAT-01:
    title: "Attenuating Agent Tokens"
    target: https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/01/
    seriesinfo:
      Internet-Draft: draft-niyikiza-oauth-attenuating-agent-tokens-01
    author:
    - name: Niki Niyikiza
    date: 2026
  ASOR-02:
    title: "Agent Delegation Chain"
    target: https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/02/
    seriesinfo:
      Internet-Draft: draft-asor-wimse-agent-delegation-chain-02
    author:
    - name: Rafael Asor
    date: 2026
  HAMR-02:
    title: "OAuth Agent Delegation"
    target: https://datatracker.ietf.org/doc/draft-hamr-oauth-agent-delegation/02/
    seriesinfo:
      Internet-Draft: draft-hamr-oauth-agent-delegation-02
    date: 2026
  COETZEE-03:
    title: "Transaction Tokens with Secure Provenance Tokens"
    target: https://datatracker.ietf.org/doc/draft-coetzee-oauth-spt-txn-tokens/03/
    seriesinfo:
      Internet-Draft: draft-coetzee-oauth-spt-txn-tokens-03
    date: 2026
  AGNIHOTRI-02:
    title: "Implementation Status of OAuth Agent Drafts"
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
delegation chains for AI agents. It describes a minimal verifier written
from each draft's text, a symbolic model of the shared chain structure
checked with ProVerif, the questions the draft texts leave open, and the
results of the model on both drafts, including two properties raised in
public review. The author of this report is not an author of either draft.
The report specifies nothing; it follows the shape of RFC 7942.

<!-- TODO(abstract): rewrite after sections 6 to 8 are argued. -->

--- middle

# Introduction

<!-- What goes here: what was done, what was not, who did it. -->

Several individual Internet-Drafts propose chains of signed tokens in which
each link can only narrow the authority of the one before it, so that a
verifier can check an agent's authority offline. This report covers two of
them, {{AAT-01}} and {{ASOR-02}}, and mentions two more, {{HAMR-02}} and
{{COETZEE-03}}.

What was done:

- A minimal TypeScript verifier for the chain checks of both drafts,
  written as an executable specification (see {{verifier}}).
- A ProVerif model {{PROVERIF}} of the shared chain structure (parent-hash
  linkage, depth, lifetime and capability monotonicity, holder binding and
  proof of possession), instantiated for both drafts (see {{model}}).
- This report.

What was not done: no minting or issuing service, no CBOR encoding, no
revocation or status-list handling, no interoperability testing against
another implementation.

Who did it: an individual, not an author of either draft. The shape and
tone of this report follow {{AGNIHOTRI-02}}. The drafts are
the object of study; the mechanisms described here are theirs.

Source code, model and vectors: TODO(url: public repository tree, `verifier/`
and `model/`).

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

"AAT-01" is {{AAT-01}}; "asor-02" is {{ASOR-02}}.

Related documents used below: {{RFC8785}} (canonical JSON, used by both
drafts for hashing and comparison), {{RFC9278}} (JWK thumbprint URI) and
{{RFC9396}} (rich authorization requests, the model for structured
authority). TODO(check each against the drafts' own use)

Finding labels A1 to A7 (asor-02), B1 to B25 (AAT-01) and M1, M2 (the two
properties of {{model-properties}}) are this document's own numbering. They
are not used by the drafts or by the reviews cited here.

# Reported Drafts {#drafts}

<!-- What goes here: one subsection per draft; what it proposes, at the
level needed to read sections 4 to 8. No evaluation. -->

## AAT-01

{{AAT-01}} (Niyikiza): TODO(description: holder-derived chain; each link
signed by the key in the parent's `cnf`; `par_hash` commitment; proof of
possession at invocation). Modelled and implemented.

## asor-02

{{ASOR-02}} (Asor): TODO(description: delegation tokens as access tokens
({{RFC9068}}) with `par_hash` and monotonic `del_depth`; verification
under configured keys; DPoP-bound leaf). Modelled and implemented.

## hamr-02 and coetzee-03

{{HAMR-02}}: TODO(one paragraph). Described here, not implemented.

{{COETZEE-03}}: TODO(one paragraph). Described here, not implemented.

# The Verifier {#verifier}

<!-- What goes here: layout, what is checked, what is not, vectors. Facts
live in verifier/README.md; point at it, do not restate. -->

The verifier is a minimal TypeScript implementation, not a product. It
verifies a chain under either profile with a shared chain walk and a
profile that supplies the named, section-tagged checks of the draft. Layout,
inputs, failure codes and options are documented in `verifier/README.md`
(TODO(url)).

It checks, for asor-02, the steps of its verification procedure up to the
action check; for AAT-01, the root, link and leaf checks of its verification
algorithm and the proof of possession. It does not implement status-list
handling (a token carrying a status claim is denied), mTLS-bound
confirmation, ES256 proofs, replay caches, or any key type other than
Ed25519. The complete list is in `verifier/README.md`.

Vectors:

- asor-02: the 35 offline-verification vectors published with the
  `attenu-guard` 0.20.0 source distribution, Apache License 2.0, copied
  unchanged; all 35 produce the outcome they name.
- AAT-01: 41 vectors written for this work from our reading of the draft.
  The draft publishes none; these are not the author's vectors.

# The Model {#model}

<!-- What goes here: abstractions, bound, attacker, properties, results,
limits. Facts live in model/README.md. -->

The model is a symbolic (Dolev-Yao) model in ProVerif's typed applied
pi-calculus. Its roles, abstractions, bound (chains of at most four tokens,
depth and expiry bounded by 3, tool sets over a three-tool alphabet) and
attacker (controls the network, may compromise any holder key, never the
trust anchor's key) are described in `model/README.md` (TODO(url)).

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

## aat {#impl-aat}

Organization:
: None (individual).

Name:
: aat (verifier and model).

Description:
: A minimal TypeScript verifier for AAT-01 and asor-02 chains, and a
  ProVerif model of both; see {{verifier}} and {{model}}.

Level of maturity:
: Research prototype; an executable specification, not a product.

Coverage:
: Chain verification for both profiles as listed in {{verifier}}; no
  minting service, no CBOR, no revocation. TODO(coverage per draft section)

Version compatibility:
: draft-niyikiza-oauth-attenuating-agent-tokens-01 and
  draft-asor-wimse-agent-delegation-chain-02.

Licensing:
: Apache License 2.0.

Implementation experience:
: TODO(argument: summary of sections 6 and 7)

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

From the repository root (TODO(url)):

- `npm --prefix verifier install`
- `npm --prefix verifier test`
- `make -C model summary`

Versions: Node 22 or later; ProVerif 2.05. TODO(exact versions used for
the reported run)

# Change Log {#changelog}

<!-- Remove before publication. -->

## -00

Initial skeleton.

# Acknowledgements
{:numbered="false"}

TODO(acknowledgements)
