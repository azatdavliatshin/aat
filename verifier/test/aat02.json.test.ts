import { test } from "node:test";
import assert from "node:assert/strict";
import { ExactNumber, parseJson, parseJsonExact } from "../src/json.js";

const enc = (s: string) => new TextEncoder().encode(s);

test("-02 §3.4 admissibility: the draft's own examples", () => {
  for (const t of ["0.1", "1e20", "9007199254740994", "-0", "0", "1152921504606847000"]) {
    assert.equal(new ExactNumber(t).admissible, true, t);
  }
  for (const t of ["9007199254740993", "1.00000000000000001", "1152921504606846976", "1e400"]) {
    assert.equal(new ExactNumber(t).admissible, false, t);
  }
});

test("-02 §3.2: integer syntax has no fraction or exponent part", () => {
  assert.equal(new ExactNumber("3").integerSyntax, true);
  assert.equal(new ExactNumber("3.0").integerSyntax, false);
  assert.equal(new ExactNumber("3e0").integerSyntax, false);
});

test("exact parse keeps the text; the default parser is unchanged", () => {
  const x = parseJsonExact(enc('{"a":9007199254740993}'), "t");
  assert.ok(x.ok);
  assert.equal(((x.value as Record<string, ExactNumber>).a as ExactNumber).text, "9007199254740993");
  const y = parseJson(enc('{"a":9007199254740993}'), "t");
  assert.equal(y.ok, false); // asor-02 §3 behaviour kept
  assert.equal(parseJsonExact(enc('{"a":1,"a":2}'), "t").ok, false);
  assert.equal(parseJsonExact(enc('{"a":1,"a":2}'), "t", { duplicates: "first" }).ok, true);
});
