import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { verifyChain } from "../src/index.js";

const dir = new URL("../vectors/asor/", import.meta.url);

interface Vector {
  description: string;
  signer: { alg: string; kid: string; secret_hex: string };
  verifier: { accepted_algs: string[]; audience: string };
  now: number;
  tokens: string[];
  expect?: "accept";
  expect_reject_reason?: string;
}

/** Vectors we expect to differ for a reason in the draft or the vectors; see the status file. */
const KNOWN_DIVERGENCES = new Map<string, string>();

const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();

test("all 35 asor-02 vectors are present", () => {
  assert.equal(files.length, 35);
});

for (const file of files) {
  const run = () => {
    const v = JSON.parse(readFileSync(new URL(file, dir), "utf8")) as Vector;
    const secret = new Uint8Array(Buffer.from(v.signer.secret_hex, "hex"));
    const result = verifyChain(v.tokens, "asor-02", {
      keys: { [v.signer.kid]: { alg: "HS256", secret } },
      acceptedAlgs: v.verifier.accepted_algs,
      now: v.now,
      audience: v.verifier.audience,
    });
    if (v.expect === "accept") {
      assert.ok(result.ok, result.ok ? "" : `${result.code} (${result.check}): ${result.message}`);
    } else {
      assert.ok(!result.ok, "expected rejection");
      assert.equal(result.code, v.expect_reject_reason, `${result.check}: ${result.message}`);
    }
  };
  const note = KNOWN_DIVERGENCES.get(file);
  if (note) test.todo(`${file}: ${note}`);
  else test(file, run);
}
