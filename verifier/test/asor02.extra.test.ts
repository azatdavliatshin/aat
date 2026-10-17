import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { parentHash, sha256b64u } from "../src/hash.js";
import { okpThumbprint } from "../src/holder.js";
import { verifyChain, type VerifyOptions } from "../src/index.js";
import type { JsonObject, JsonValue } from "../src/json.js";
import { signJws, signRaw } from "../src/testing/sign.js";

// Checks the vectors do not exercise: depth, validity window, canonical form,
// status references, holder binding (step 6) and the action check (step 8).

const secret = new Uint8Array(32).fill(9);
const key = { alg: "HS256", secret } as const;
const base: VerifyOptions = { keys: { k: { alg: "HS256", secret } }, acceptedAlgs: ["HS256"], now: 100, audience: "https://rp.example" };
const cnf = { jkt: "AAAA" };

function detail(extra: JsonValue[] = [], scopes = ["crm.*"]): JsonValue {
  return [{ type: "agent_delegation", scopes, constraints: extra }];
}

function claims(i: number, over: Partial<Record<string, JsonValue>> = {}, par?: string): Record<string, JsonValue> {
  return {
    iss: "i", jti: `j${i}`, sub: "p", client_id: `a${i}`, aud: "https://rp.example", cnf,
    iat: 0, exp: 1000 - i, nbf: 0, del_depth: i, ...(i === 0 && { del_max_depth: 3 }),
    authorization_details: detail(), ...(par && { par_hash: par }), ...over,
  };
}

function chain(n: number, over: (i: number) => Partial<Record<string, JsonValue>> = () => ({})): string[] {
  const out: string[] = [];
  for (let i = 0; i < n; i++) out.push(signJws(claims(i, over(i), i ? parentHash(out[i - 1]!) : undefined), key, { kid: "k" }));
  return out;
}

const code = (tokens: string[], o: Partial<VerifyOptions> = {}) => {
  const r = verifyChain(tokens, "asor-02", { ...base, ...o });
  return r.ok ? "accept" : r.code;
};

test("baseline chain verifies and reports steps 6 as not performed", () => {
  const r = verifyChain(chain(3), "asor-02", base);
  assert.ok(r.ok);
  assert.ok(!r.stepsPerformed.includes(6));
});

test("step 3: depth out of sequence, chain at del_max_depth", () => {
  assert.equal(code(chain(2, (i) => (i === 1 ? { del_depth: 2 } : {}))), "depth_invalid");
  assert.equal(code(chain(4)), "depth_invalid"); // n = 3, del_max_depth = 3
  assert.equal(code(chain(3)), "accept");
});

test("step 5: expired and not yet valid", () => {
  assert.equal(code(chain(2), { now: 5000 }), "expired");
  assert.equal(code(chain(2, () => ({ nbf: 200 }))), "expired");
});

test("§3: JCS is enforced on the payload and the header; duplicates are named", () => {
  const enc = (s: string) => new TextEncoder().encode(s);
  const h = enc('{"alg":"HS256","kid":"k","typ":"at+jwt"}');
  const reordered = signRaw(h, enc('{"b":1,"a":2}'), key);
  assert.equal(code([reordered]), "non_canonical");
  const spaced = signRaw(enc('{"alg":"HS256", "kid":"k","typ":"at+jwt"}'), enc("{}"), key);
  assert.equal(code([spaced]), "non_canonical");
  const dup = signRaw(h, enc('{"a":1,"a":2}'), key);
  assert.equal(code([dup]), "duplicate_member");
  assert.equal(code([signRaw(h, enc('{"a":1e999}'), key)]), "non_finite");
  assert.equal(code([signRaw(h, enc('{"a":"\\ud800"}'), key)]), "malformed");
});

test("§3: typ must be at+jwt, par_hash absent in DT_0, required below", () => {
  assert.equal(code([signJws(claims(0), key, { kid: "k", typ: "JWT" })]), "malformed");
  assert.equal(code([signJws(claims(0, { par_hash: "x" }), key, { kid: "k" })]), "malformed");
  assert.equal(code([signJws(claims(0), key, { kid: "k" }), signJws(claims(1), key, { kid: "k" })]), "malformed");
});

test("step 7: a status reference cannot be checked and denies with a distinct code", () => {
  assert.equal(code(chain(2, (i) => (i === 1 ? { status: { status_list: { idx: 1, uri: "https://s" } } } : {}))), "not_implemented");
});

test("step 4: scope wildcard depth and sibling namespace", () => {
  const widen = (scopes: string[]) => code(chain(2, (i) => (i === 1 ? { authorization_details: detail([], scopes) } : {})));
  assert.equal(widen(["crm.x.y.z", "crm.x.*"]), "accept");
  assert.equal(widen(["crmx.read"]), "not_narrower");
  assert.equal(widen(["crm"]), "not_narrower"); // bare "crm" is an opaque scope; crm.* covers neither it nor crmx.read
});

test("step 4: one_of, not_one_of, prefix, min narrow in their own direction", () => {
  const p: JsonValue[] = [
    { key: "a", one_of: [1, 2, 3] }, { key: "b", not_one_of: ["x"] }, { key: "c", prefix: "/srv" }, { key: "d", min: 2 },
  ];
  const ok: JsonValue[] = [
    { key: "a", one_of: [2] }, { key: "b", not_one_of: ["x", "y"] }, { key: "c", prefix: "/srv/a" }, { key: "d", min: 3 },
  ];
  const run = (child: JsonValue[]) =>
    code(chain(2, (i) => ({ authorization_details: detail(i === 0 ? p : child) })));
  assert.equal(run(ok), "accept");
  assert.equal(run([{ key: "a", one_of: [4] }, ...ok.slice(1)]), "not_narrower");
  assert.equal(run([ok[0]!, { key: "b", not_one_of: [] }, ...ok.slice(2)]), "not_narrower");
  assert.equal(run([...ok.slice(0, 2), { key: "c", prefix: "/s" }, ok[3]!]), "not_narrower");
  assert.equal(run([...ok.slice(0, 3), { key: "d", min: 1 }]), "not_narrower");
});

// ------------------------------------------------------------- step 6

const holder = generateKeyPairSync("ed25519");
const jwk = holder.publicKey.export({ format: "jwk" }) as JsonObject;
const holderCnf = { jkt: okpThumbprint(jwk) };

function proof(leaf: string, over: Record<string, JsonValue> = {}, signWith = holder.privateKey): string {
  const header = { alg: "EdDSA", typ: "dpop+jwt", jwk: { crv: jwk.crv, kty: jwk.kty, x: jwk.x } };
  const payload = { jti: "p1", htm: "POST", htu: "https://rp.example/act", iat: 100, ath: sha256b64u(new TextEncoder().encode(leaf)), ...over };
  return signJws(payload as JsonValue, { alg: "EdDSA", privateKey: signWith }, header as JsonValue as Record<string, JsonValue>);
}

test("step 6: DPoP proof bound to the leaf, request and cnf", () => {
  const tokens = chain(2, (i) => (i === 1 ? { cnf: holderCnf } : {}));
  const leaf = tokens[1]!;
  const run = (p: string, method = "POST", url = "https://rp.example/act?x=1") =>
    code(tokens, { request: { dpop: { proof: p, method, url } } });
  assert.equal(run(proof(leaf)), "accept");
  assert.equal(run(proof(leaf), "GET"), "holder_binding_failed");
  assert.equal(run(proof(leaf), "POST", "https://rp.example/other"), "holder_binding_failed");
  assert.equal(run(proof(leaf, { iat: 5000 })), "holder_binding_failed");
  assert.equal(run(proof(leaf, { ath: "AAAA" })), "holder_binding_failed");
  assert.equal(run(proof(tokens[0]!)), "holder_binding_failed"); // proof for another token
  const other = generateKeyPairSync("ed25519");
  assert.equal(run(proof(leaf, {}, other.privateKey)), "holder_binding_failed"); // header jwk does not match signer
  assert.equal(run("not-a-jws"), "holder_binding_failed");
  assert.equal(code(chain(2), { request: { dpop: { proof: proof(leaf), method: "POST", url: "https://rp.example/act" } } }), "holder_binding_failed"); // cnf.jkt is another key
});

// ------------------------------------------------------------- step 8

test("step 8: scope, per-action and cumulative constraints, unknown types", () => {
  const cons: JsonValue[] = [{ key: "rows", max: 10 }, { key: "calls", max_lifetime: 5 }];
  const tokens = chain(1, () => ({ authorization_details: detail(cons, ["crm.*"]) }));
  const act = (scope: string, params: Record<string, unknown>, totals?: Record<string, number>) =>
    code(tokens, { request: { action: { scope, params }, ...(totals && { totals }) } });
  assert.equal(act("crm.read", { rows: 10 }, { calls: 5 }), "accept");
  assert.equal(act("mail.send", { rows: 1 }, { calls: 0 }), "scope_not_granted");
  assert.equal(act("crm.read", { rows: 11 }, { calls: 0 }), "ceiling_exceeded");
  assert.equal(act("crm.read", {}, { calls: 0 }), "ceiling_exceeded"); // absent value fails closed
  assert.equal(act("crm.read", { rows: 1 }), "ceiling_exceeded"); // no running total supplied: deny
  assert.equal(act("crm.read", { rows: 1, calls: 0 }), "ceiling_exceeded"); // a total claimed by the request is not a total
  assert.equal(act("crm.read", { rows: 1 }, { calls: 6 }), "ceiling_exceeded");
  const unk = chain(1, () => ({ authorization_details: detail([{ key: "q", units: 1 }]) }));
  assert.equal(code(unk, { request: { action: { scope: "crm.read" } } }), "unknown_constraint");
});

test("signature step precedes profile checks and DT_0 must be signed", () => {
  const t = chain(2);
  assert.equal(code(t, { keys: {} }), "signature_invalid");
});
