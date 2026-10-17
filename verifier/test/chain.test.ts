import assert from "node:assert/strict";
import { test } from "node:test";
import { walkChain, type Profile, type VerifyOptions } from "../src/chain.js";
import { parentHash } from "../src/hash.js";
import { isObject } from "../src/json.js";
import { parseJson } from "../src/json.js";
import { fail } from "../src/result.js";
import { signJws } from "../src/testing/sign.js";

const secret = new Uint8Array(32).fill(1);
const key = { alg: "HS256", secret } as const;
const opts: VerifyOptions = { keys: { k: { alg: "HS256", secret } }, acceptedAlgs: ["HS256"], now: 0 };

interface Toy { par?: string; fatal?: boolean }

const toy: Profile<Toy> = {
  name: "toy",
  parse(jws) {
    const p = parseJson(jws.payloadBytes, "toy");
    if (!p.ok) return p;
    if (!isObject(p.value)) return fail("malformed", "toy", "object expected");
    return { ok: true, value: { par: p.value.par as string | undefined, fatal: p.value.fatal === true } };
  },
  declaredParentHash: (c) => c.par,
  tokenChecks: (n) => [{ name: "fatal", step: 5, seq: 0, token: n.index, run: () => (n.claims.fatal ? { code: "expired", section: "toy", message: "x" } : undefined) }],
  rootChecks: () => [],
  linkChecks: () => [],
  leafChecks: () => [],
};

const mint = (claims: Record<string, string | boolean>) => signJws(claims, key, { kid: "k" });

function chainOf(n: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    out.push(mint(i === 0 ? { i: "0" } : { par: parentHash(out[i - 1]!) }));
  }
  return out;
}

test("walkChain accepts a linked chain and reports performed steps", () => {
  const r = walkChain(chainOf(3), toy, opts);
  assert.ok(r.ok);
  assert.deepEqual(r.stepsPerformed, [1, 2, 5]);
});

test("walkChain: par_hash mismatch names token and check", () => {
  const c = chainOf(3);
  c[1] = mint({ par: parentHash(c[0]!), extra: "re-issued" });
  const r = walkChain(c, toy, opts);
  assert.ok(!r.ok);
  assert.equal(r.code, "par_hash_mismatch");
  assert.equal(r.token, 2);
  assert.equal(r.check, "par_hash");
});

test("walkChain: step order, not token order (signature before profile check)", () => {
  const c = chainOf(2);
  c[0] = mint({ i: "0", fatal: true });
  const wrongKey = walkChain(c, toy, { ...opts, keys: { k: { alg: "HS256", secret: new Uint8Array(32) } } });
  assert.ok(!wrongKey.ok);
  assert.equal(wrongKey.code, "signature_invalid");
});

test("walkChain: alg off the accepted list is denied even if the signature verifies", () => {
  const r = walkChain(chainOf(1), toy, { ...opts, acceptedAlgs: ["EdDSA"] });
  assert.ok(!r.ok && r.code === "signature_invalid");
});

test("walkChain: unknown kid and empty list", () => {
  const r = walkChain(chainOf(1), toy, { ...opts, keys: {} });
  assert.ok(!r.ok && r.code === "signature_invalid");
  assert.throws(() => walkChain([], toy, opts));
});
