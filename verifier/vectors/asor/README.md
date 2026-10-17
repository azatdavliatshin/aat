# asor -02 test vectors

Copied byte for byte from the `attenu-guard` 0.20.0 source distribution
(PyPI), `tests/vectors-02/`, published with
draft-asor-wimse-agent-delegation-chain-02 (Appendix B). Fetched 2026-10-17.
Licence: Apache License 2.0, Copyright 2026 Attenu (see `LICENSE` and
`NOTICE` in the upstream package; reproduced here).

Each file names the verifier configuration (`signer`, `verifier`), the
evaluation time (`now`), the token chain (`tokens`) and the expected
outcome (`expect`). The signer is a public HS256 test key, not a key a
real deployment would use.
