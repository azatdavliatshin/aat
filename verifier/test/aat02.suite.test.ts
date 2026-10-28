import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { loadSuite, runSuite, SUITE_PATH, type VectorRun } from "../src/testing/aat02-suite.js";

/**
 * The AAT-02 JWS vector suite as a regression test: every vector that is not
 * SKIP must get the suite's verdict. Remaining disagreements, if any, are
 * listed in `KNOWN` with their classification and the test for them is `todo`.
 */

const SHA256 = "b7a42e9dfdce7fbc1f623670bf060f90e6d6b25f64384cbab1bd79363e82209b";
/** id -> why we disagree (a draft ambiguity, kept on purpose). Empty: no disagreement remains. */
const KNOWN: Readonly<Record<string, string>> = {};

const suite = loadSuite();
const verdict = (r: VectorRun["result"]): string => (typeof r === "string" ? r : r.verdict);
const step = (r: VectorRun["result"]): string | undefined => (typeof r === "object" && "step" in r ? r.step : undefined);

test("the suite file is the one the results name", () => {
  assert.equal(createHash("sha256").update(readFileSync(SUITE_PATH)).digest("hex"), SHA256);
  assert.equal(suite.vectors.length, 229);
});

for (const form of ["presentation", "arrays"] as const) {
  test(`every non-SKIP vector gets the expected verdict (${form} input)`, () => {
    const runs = runSuite(suite, form);
    const differ = runs
      .map((r, i) => ({ r, v: suite.vectors[i]! }))
      .filter(({ r, v }) => verdict(r.result) !== "SKIP" && verdict(r.result) !== v.expected.verdict && !(v.id in KNOWN))
      .map(({ r, v }) => `${v.id} ${v.title}: expected ${v.expected.verdict}, got ${verdict(r.result)} (${JSON.stringify(r.result)})`);
    assert.deepEqual(differ, []);
  });
}

test("known disagreements (draft ambiguities)", { todo: Object.keys(KNOWN).length > 0 }, () => {
  assert.deepEqual(Object.keys(KNOWN), []);
});

test("a DENY is reported at the suite's step (information: §8 permits reordering)", () => {
  const runs = runSuite(suite);
  const differ = runs
    .map((r, i) => ({ r, v: suite.vectors[i]! }))
    .filter(({ r, v }) => verdict(r.result) === "DENY" && v.expected.verdict === "DENY" && step(r.result) !== v.expected.step)
    .map(({ r, v }) => `${v.id}: expected ${v.expected.step}, got ${step(r.result)}`);
  assert.deepEqual(differ, []);
});

test("step 7i: the replay cache after each tracked vector is the suite's", () => {
  const runs = runSuite(suite);
  for (const [i, v] of suite.vectors.entries()) {
    if (!v.replay_state) continue;
    assert.deepEqual(runs[i]!.replayAfter, v.replay_state.after, v.id);
  }
});
