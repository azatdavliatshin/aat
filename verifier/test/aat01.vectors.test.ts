import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { createPublicKey } from "node:crypto";
import { verifyChain } from "../src/index.js";
import type { AatOptions } from "../src/profiles/aat01.js";
import { buildVectors, type AatVector } from "../src/testing/aat-vectors.js";

const dir = new URL("../vectors/aat/", import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();

test("at least 20 AAT-01 vectors are present", () => {
  assert.ok(files.length >= 20, `${files.length} vectors`);
});

test("the files are exactly what the generator produces (deterministic)", () => {
  const generated = buildVectors();
  assert.deepEqual(files, generated.map((v) => `${v.name}.json`).sort());
  for (const v of generated) {
    assert.equal(readFileSync(new URL(`${v.name}.json`, dir), "utf8"), JSON.stringify(v, null, 2) + "\n", v.name);
  }
});

for (const file of files) {
  test(file, () => {
    const v = JSON.parse(readFileSync(new URL(file, dir), "utf8")) as AatVector;
    const result = verifyChain(v.chain, "aat-01", {
      trustAnchors: v.trust_anchors.map((jwk) => ({ alg: "EdDSA" as const, publicKey: createPublicKey({ key: jwk as never, format: "jwk" }) })),
      now: v.now,
      aat: v.options as AatOptions,
      ...(v.request && v.pop && { request: { aat: { tool: v.request.tool, args: v.request.args, pop: v.pop } } }),
    });
    if (v.expect.outcome === "accept") {
      assert.ok(result.ok, result.ok ? "" : `${result.code} (${result.check}): ${result.message}`);
    } else {
      assert.ok(!result.ok, "expected rejection");
      assert.equal(result.code, v.expect.code, `${result.check}: ${result.message}`);
      assert.equal(result.check, v.expect.check);
    }
  });
}
