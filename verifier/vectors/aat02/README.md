# AAT-02 JWS vectors

`aat-jws-vectors.json` is the author's byte-exact JWS test-vector suite for
`draft-niyikiza-oauth-attenuating-agent-tokens-02`: 229 vectors, each with
the expected verdict and the first failing step of the draft's §8 algorithm.
It is copied unmodified from the Tenuo repository (see `NOTICE`; Apache-2.0,
see `LICENSE`). Run it with `npm run suite:aat02`, which writes
`results/aat02-results.json` in the format of the suite's `compare_results.py`.
`npm test` runs it too, as `test/aat02.suite.test.ts`. SHA-256 of the file:
`b7a42e9dfdce7fbc1f623670bf060f90e6d6b25f64384cbab1bd79363e82209b`.
