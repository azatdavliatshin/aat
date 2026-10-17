import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import fc from "fast-check";
import { b64urlDecode, b64urlEncode } from "../src/encoding.js";
import { verifyChain } from "../src/index.js";

const vector = new URL("../vectors/asor/valid_chain.json", import.meta.url);

test("asor valid_chain vector parses as JSON", (t) => {
  let raw: string;
  try {
    raw = readFileSync(vector, "utf8");
  } catch {
    t.skip("asor vectors not present");
    return;
  }
  const data = JSON.parse(raw) as { tokens: string[]; expect: string };
  assert.equal(data.expect, "accept");
  assert.ok(data.tokens.length > 0);
});

test("base64url round trip", () => {
  fc.assert(
    fc.property(fc.uint8Array(), (bytes) => {
      const text = b64urlEncode(bytes);
      assert.match(text, /^[A-Za-z0-9_-]*$/);
      assert.deepEqual(b64urlDecode(text), bytes);
    }),
  );
});

test("verifyChain is a placeholder", () => {
  assert.throws(() => verifyChain([], "asor-02"), /not implemented/);
});
