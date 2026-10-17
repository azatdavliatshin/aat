import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import fc from "fast-check";
import { b64urlEncode } from "../src/encoding.js";
import { parentHash, sha256b64u, signingInput } from "../src/hash.js";
import { parseJws, verifyJws, type TrustedKey } from "../src/jws.js";
import { signJws, signRaw, type SigningKey } from "../src/testing/sign.js";

const ed = generateKeyPairSync("ed25519");
const edSign: SigningKey = { alg: "EdDSA", privateKey: ed.privateKey };
const edTrust: TrustedKey = { alg: "EdDSA", publicKey: ed.publicKey };
const secret = new Uint8Array(32).fill(7);
const hsSign: SigningKey = { alg: "HS256", secret };
const hsTrust: TrustedKey = { alg: "HS256", secret };
const pairs: Array<[SigningKey, TrustedKey]> = [[edSign, edTrust], [hsSign, hsTrust]];

const json = fc.dictionary(fc.string({ maxLength: 8 }), fc.oneof(fc.string({ maxLength: 12 }), fc.integer({ min: -1000, max: 1000 }), fc.boolean()), { maxKeys: 5 });

function accepts(compact: string, trust: TrustedKey): boolean {
  const p = parseJws(compact);
  return p.ok && verifyJws(p.value, trust);
}

test("sign -> verify round trip, both algs", () => {
  fc.assert(
    fc.property(json, (payload) => {
      for (const [s, t] of pairs) assert.ok(accepts(signJws(payload, s), t));
    }),
  );
});

test("changing any character of header, payload or signature fails verification", () => {
  fc.assert(
    fc.property(json, fc.nat(), fc.nat(), (payload, at, shift) => {
      for (const [s, t] of pairs) {
        const token = signJws(payload, s);
        const i = at % token.length;
        if (token[i] === ".") continue;
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        const replacement = alphabet[(alphabet.indexOf(token[i] as string) + 1 + (shift % 63)) % 64] as string;
        const tampered = token.slice(0, i) + replacement + token.slice(i + 1);
        assert.notEqual(tampered, token);
        assert.equal(accepts(tampered, t), false, `byte ${i} of ${s.alg} token`);
      }
    }),
  );
});

test("flipping any bit of the decoded signature fails verification", () => {
  fc.assert(
    fc.property(json, fc.nat(), (payload, bit) => {
      for (const [s, t] of pairs) {
        const p = parseJws(signJws(payload, s));
        assert.ok(p.ok);
        const sig = Uint8Array.from(p.value.signature);
        sig[Math.floor(bit / 8) % sig.length]! ^= 1 << (bit % 8);
        assert.equal(verifyJws({ ...p.value, signature: sig }, t), false);
      }
    }),
  );
});

test("signingInput is the byte string that was signed", () => {
  fc.assert(
    fc.property(json, (payload) => {
      for (const [s] of pairs) {
        const token = signJws(payload, s);
        const [h, p] = token.split(".");
        assert.deepEqual(signingInput(token), new Uint8Array(Buffer.from(`${h}.${p}`, "ascii")));
        const parsed = parseJws(token);
        assert.ok(parsed.ok);
        assert.deepEqual(parsed.value.signingInput, signingInput(token));
      }
    }),
  );
});

test("a verifier configured for one alg refuses the other", () => {
  assert.equal(accepts(signJws({}, hsSign), edTrust), false);
  assert.equal(accepts(signJws({}, edSign), hsTrust), false);
});

test("strict parse: alg none, unknown alg, shape and padding are refused", () => {
  const enc = (o: unknown) => b64urlEncode(new Uint8Array(Buffer.from(JSON.stringify(o))));
  const none = `${enc({ alg: "none" })}.${enc({})}.`;
  const noneP = parseJws(none);
  assert.ok(!noneP.ok && noneP.code === "alg_none");
  const rs = parseJws(`${enc({ alg: "RS256" })}.${enc({})}.AA`);
  assert.ok(!rs.ok && rs.code === "alg_unsupported");
  const good = signJws({ a: 1 }, hsSign);
  for (const bad of [`${good}.x`, good.split(".").slice(0, 2).join("."), `${good}=`, "", "..", `${good} `]) {
    const r = parseJws(bad);
    assert.ok(!r.ok && r.code === "malformed", bad);
  }
  const dup = signRaw(new TextEncoder().encode('{"alg":"HS256","alg":"HS256"}'), new TextEncoder().encode("{}"), hsSign);
  const d = parseJws(dup);
  assert.ok(!d.ok && d.code === "duplicate_member");
});

test("non-canonical base64url (non-zero trailing bits) is refused", () => {
  const good = signJws({}, hsSign);
  const [h, p, s] = good.split(".") as [string, string, string];
  // HS256 signature is 32 bytes -> 43 chars, last char carries 2 spare bits.
  const last = s[s.length - 1]!;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const alt = alphabet[(alphabet.indexOf(last) + 1) % 64]!;
  assert.ok(!parseJws(`${h}.${p}.${s.slice(0, -1)}${alt}`).ok);
});

test("hash helpers", () => {
  assert.equal(sha256b64u(new Uint8Array()), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
  const t = signJws({ x: 1 }, hsSign);
  assert.equal(parentHash(t), sha256b64u(signingInput(t)));
});
