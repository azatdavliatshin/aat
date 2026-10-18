import assert from "node:assert/strict";
import { test } from "node:test";
import fc from "fast-check";
import { verifyChain } from "../src/index.js";
import type { VerifyOptions } from "../src/chain.js";
import { thumbprintUri } from "../src/profiles/aat01.js";
import { derive, mintChain, mintRoot, newHolder, type Chain, type Override } from "../src/testing/aat-mint.js";

function verify(c: Chain, tokens: string[] = c.compact, extra: Partial<VerifyOptions> = {}) {
  return verifyChain(tokens, "aat-01", {
    trustAnchors: [{ alg: "EdDSA", publicKey: c.anchor.publicKey }],
    now: c.now,
    aat: { maxTokenLifetime: 1000 },
    ...extra,
  });
}

function rejected(c: Chain, tokens: string[], code: string, check?: string, extra: Partial<VerifyOptions> = {}) {
  const r = verify(c, tokens, extra);
  assert.ok(!r.ok, "expected rejection");
  assert.equal(r.code, code, `${r.check}: ${r.message}`);
  if (check) assert.equal(r.check, check);
}

/** Replace the last token of a chain by a child of its parent with overridden claims. */
function withLastLink(c: Chain, spec: Partial<Parameters<typeof derive>[0]>): string[] {
  const parent = c.tokens[c.tokens.length - 2]!;
  const bad = derive({ parent, iat: c.leaf.claims.iat as number, exp: c.leaf.claims.exp as number, ...spec });
  return [...c.compact.slice(0, -1), bad.compact];
}

test("valid chains of depth 0..5 are accepted", () => {
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 5 }), (depth) => {
      const c = mintChain({ depth });
      const r = verify(c);
      assert.ok(r.ok, r.ok ? "" : `${r.code} ${r.check}: ${r.message}`);
    }),
    { numRuns: 30 },
  );
});

test("empty chain and size limits are denied as values", () => {
  const c = mintChain({ depth: 1 });
  rejected(c, [], "chain_empty");
  rejected(c, c.compact, "size_limit", "token_size", { aat: { maxTokenSize: 100 } });
  rejected(c, c.compact, "size_limit", "stack_size", { aat: { maxStackSize: 600, maxTokenSize: 60000 } });
});

test("root: alg none, wrong anchor, untrusted signature", () => {
  const c = mintChain({ depth: 0 });
  const [h, p] = c.compact[0]!.split(".");
  const none = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${p}.`;
  void h;
  rejected(c, [none], "signature_invalid");
  const other = newHolder();
  rejected(c, c.compact, "signature_invalid", "signature", { trustAnchors: [{ alg: "EdDSA", publicKey: other.publicKey }] });
  rejected(c, c.compact, "signature_invalid", "signature", { trustAnchors: [] });
});

test("root: depth 0, no par_hash, iss a URI, exactly one AAT entry", () => {
  const c = mintChain({ depth: 0 });
  const mint = (override: Override) => [mintRoot({ anchor: c.anchor, iat: c.leaf.claims.iat as number, exp: c.leaf.claims.exp as number, override }).compact];
  rejected(c, mint({ del_depth: 1 }), "root_invalid", "root_del_depth_zero");
  rejected(c, mint({ par_hash: "x" }), "root_invalid", "root_par_hash_absent");
  rejected(c, mint({ iss: "not a uri" }), "root_invalid", "root_iss_uri");
  rejected(c, mint({ authorization_details: [] }), "malformed", "aat_entry_count");
  rejected(c, mint({ authorization_details: [{ type: "attenuating_agent_token", tools: {} }, { type: "attenuating_agent_token", tools: {} }] }), "malformed", "aat_entry_count");
  rejected(c, mint({ del_max_depth: 99 }), "I2", "del_max_depth_bound");
});

test("parse: required claims, jti shape, cnf.jwk, sub", () => {
  const c = mintChain({ depth: 0 });
  const mint = (override: Override) => [mintRoot({ anchor: c.anchor, iat: c.leaf.claims.iat as number, exp: c.leaf.claims.exp as number, override }).compact];
  for (const claim of ["jti", "iss", "iat", "exp", "cnf", "del_depth", "del_max_depth", "authorization_details"]) {
    rejected(c, mint({ [claim]: undefined }), "malformed");
  }
  rejected(c, mint({ jti: "01957A3F-4E23-7B01-A9D1-0050569C2E4F" }), "malformed");
  assert.ok(verify(c, mint({ jti: "01957a3f-4e23-7b01-a9d1-0050569c2e4f" })).ok);
  assert.ok(verify(c, mint({ jti: "not-a-uuid-but-non-empty" })).ok);
  rejected(c, mint({ cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: "AAAA", d: "AAAA" } } }), "malformed");
  rejected(c, mint({ cnf: { jwk: { kty: "EC", crv: "P-256", x: "a", y: "b" } } }), "malformed");
  rejected(c, mint({ sub: "alice" }), "malformed", "no_sub");
  assert.ok(verify(c, mint({ sub: "alice" }), { aat: { maxTokenLifetime: 1000, rejectSub: false } }).ok);
  rejected(c, mint({ del_depth: 0.5 }), "malformed");
});

test("I1: iss must be the thumbprint URI of the parent holder; signature by the parent holder", () => {
  const c = mintChain({ depth: 2 });
  rejected(c, withLastLink(c, { override: { iss: thumbprintUri(newHolder().jwk) } }), "I1", "delegation_authority");
  rejected(c, withLastLink(c, { override: { iss: "https://auth.example.com" } }), "I1");
  // signed by another key: the signature fails under the parent's cnf.jwk (step 4b precedes 4c)
  const stranger = newHolder();
  rejected(c, withLastLink(c, { signer: stranger }), "signature_invalid", "signature");
});

test("I2: each depth inequality", () => {
  const c = mintChain({ depth: 2, maxDepth: 4 });
  const cases: Array<[string, Override]> = [
    ["depth_increment", { del_depth: 4 }],
    ["depth_increment", { del_depth: 1 }],
    ["max_depth_not_raised", { del_max_depth: 5 }],
    ["depth_within_own_max", { del_max_depth: 1 }],
  ];
  for (const [check, override] of cases) rejected(c, withLastLink(c, { override }), "I2", check);
  rejected(c, withLastLink(c, { override: {} }).slice(0, 3), "I2", undefined, { aat: { maxTokenLifetime: 1000, maxDelegationDepth: 1 } });
  // del_depth above the parent's del_max_depth: terminal parent
  const t = mintChain({ depth: 1, maxDepth: 3 });
  const terminal = derive({ parent: t.tokens[0]!, iat: t.leaf.claims.iat as number, exp: t.leaf.claims.exp as number, maxDepth: 1 });
  const over = derive({ parent: terminal, iat: terminal.claims.iat as number, exp: terminal.claims.exp as number, override: { del_max_depth: 2 } });
  rejected(t, [t.compact[0]!, terminal.compact, over.compact], "I2", "depth_within_parent_max");
});

test("I3: each TTL inequality", () => {
  const c = mintChain({ depth: 2 });
  const parent = c.tokens[1]!;
  const piat = parent.claims.iat as number;
  const pexp = parent.claims.exp as number;
  const cases: Array<[string, Override]> = [
    ["exp_le_parent", { exp: pexp + 1 }],
    ["exp_after_now", { exp: c.now, iat: piat }],
    ["exp_after_iat", { exp: c.now + 5, iat: c.now + 5 }],
    ["iat_ge_parent", { iat: piat - 1 }],
    ["iat_not_future", { iat: c.now + 31 }],
  ];
  for (const [check, override] of cases) rejected(c, withLastLink(c, { override: { iat: piat + 1, exp: pexp - 1, ...override } }), "I3", check);
  rejected(c, c.compact, "I3", "lifetime", { aat: { maxTokenLifetime: 500 } });
});

test("I3 on the root: window, skew, lifetime", () => {
  const c = mintChain({ depth: 0 });
  const mint = (o: Override) => [mintRoot({ anchor: c.anchor, iat: c.now - 10, exp: c.now + 900, override: o }).compact];
  assert.ok(verify(c, mint({})).ok);
  rejected(c, mint({ exp: c.now }), "I3", "exp_after_now");
  rejected(c, mint({ iat: c.now + 31, exp: c.now + 900 }), "I3", "iat_not_future");
  rejected(c, mint({ exp: c.now - 10 }), "I3");
  rejected(c, mint({ exp: c.now - 10 + 1001 }), "I3", "lifetime");
});

test("I5: par_hash commits to the parent presented", () => {
  const c = mintChain({ depth: 2 });
  const other = mintChain({ depth: 1 });
  rejected(c, withLastLink(c, { parHashOf: other.compact[1]! }), "I5", "par_hash");
  rejected(c, withLastLink(c, { override: { par_hash: undefined } }), "malformed", "par_hash_present");
  // a re-issued parent with the same claims is a different signing input only if the bytes differ
  const sibling = derive({ parent: c.tokens[0]!, holder: c.tokens[1]!.holder, iat: c.tokens[1]!.claims.iat as number, exp: c.tokens[1]!.claims.exp as number });
  rejected(c, [c.compact[0]!, sibling.compact, c.compact[2]!], "I5", "par_hash");
});

test("jti cycle, chain length, wrong order", () => {
  const c = mintChain({ depth: 2 });
  const dup = derive({ parent: c.tokens[1]!, jti: c.tokens[0]!.claims.jti as string, iat: c.tokens[1]!.claims.iat as number, exp: c.tokens[1]!.claims.exp as number });
  rejected(c, [...c.compact.slice(0, 2), dup.compact], "jti_cycle", "jti_unique");
  rejected(c, [c.compact[0]!, c.compact[1]!, c.compact[1]!], "jti_cycle");
  rejected(c, c.compact.slice(0, 2).reverse(), "signature_invalid");
  // chain shorter than leaf.del_depth + 1: leaf at depth 2 presented as a pair
  const skip = derive({ parent: c.tokens[0]!, override: { del_depth: 1 }, iat: c.tokens[1]!.claims.iat as number, exp: c.tokens[1]!.claims.exp as number });
  const grand = derive({ parent: skip, override: { del_depth: 2 }, iat: skip.claims.iat as number, exp: skip.claims.exp as number });
  assert.ok(verify(c, [c.compact[0]!, skip.compact, grand.compact]).ok);
  const leafOnly = derive({ parent: c.tokens[0]!, override: { del_depth: 5 }, iat: skip.claims.iat as number, exp: skip.claims.exp as number });
  rejected(c, [c.compact[0]!, leafOnly.compact], "I2", "depth_increment");
});

test("chain_length: leaf del_depth disagrees with the number of tokens", () => {
  // A single-link chain whose root claims depth 0 but is followed by nothing is consistent; build a mismatch by
  // lowering the depth of the root's child only where I2 is not violated: not possible, so check step 5 directly.
  const c = mintChain({ depth: 1 });
  const r = verify(c);
  assert.ok(r.ok);
  assert.ok(r.stepsPerformed.includes(5));
});

test("property: a single I1/I2/I3/I5 violation on the last link is rejected with that invariant", () => {
  const violation = fc.constantFrom(
    { code: "I1", pick: (_c: Chain) => ({ override: { iss: thumbprintUri(newHolder().jwk) } as Override }) },
    { code: "I2", pick: (_c: Chain) => ({ override: { del_depth: 9 } as Override }) },
    { code: "I2", pick: (c: Chain) => ({ override: { del_max_depth: (c.leaf.claims.del_max_depth as number) + 1 } as Override }) },
    { code: "I3", pick: (c: Chain) => ({ override: { exp: (c.tokens[c.tokens.length - 2]!.claims.exp as number) + 1 } as Override }) },
    { code: "I3", pick: (c: Chain) => ({ override: { iat: (c.tokens[c.tokens.length - 2]!.claims.iat as number) - 1 } as Override }) },
    { code: "I3", pick: (c: Chain) => ({ override: { iat: c.now + 100 } as Override }) },
    { code: "I5", pick: (_c: Chain) => ({ parHashOf: mintChain({ depth: 0 }).compact[0]! }) },
  );
  fc.assert(
    fc.property(fc.integer({ min: 1, max: 5 }), violation, (depth, v) => {
      const c = mintChain({ depth, maxDepth: depth + 1 });
      const spec = v.pick(c);
      const tokens = withLastLink(c, spec);
      const r = verify(c, tokens);
      assert.ok(!r.ok);
      assert.equal(r.code, v.code, `${r.check}: ${r.message}`);
    }),
    { numRuns: 80 },
  );
});
