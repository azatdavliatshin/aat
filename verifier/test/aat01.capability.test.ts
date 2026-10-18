import assert from "node:assert/strict";
import { test } from "node:test";
import fc from "fast-check";
import { verifyChain } from "../src/index.js";
import type { VerifyOptions } from "../src/chain.js";
import { constraintDepth, parseConstraint, satisfies, subsumes, type Constraint } from "../src/profiles/aat01-constraints.js";
import type { JsonValue } from "../src/json.js";
import { mintChain, mintPop, newHolder, type Chain, type Tools } from "../src/testing/aat-mint.js";

const C = (raw: JsonValue): Constraint => {
  const c = parseConstraint(raw);
  assert.ok(!("kind" in c), "kind" in c ? c.message : "");
  return c as Constraint;
};

// ----------------------------------------------------------------- generators

const scalar = fc.constantFrom<JsonValue>(1, 2, 3, "a", "b", true);
const smallSet = fc.uniqueArray(scalar, { maxLength: 4, selector: (v) => JSON.stringify(v) });
const bound = fc.option(fc.integer({ min: -3, max: 3 }), { nil: undefined });

const leafRaw: Record<string, fc.Arbitrary<JsonValue>> = {
  exact: scalar.map((value) => ({ constraint_type: "exact", value })),
  range: fc.record({ min: bound, max: bound, mi: fc.boolean(), xi: fc.boolean() }).map(({ min, max, mi, xi }) => ({
    constraint_type: "range",
    ...(min !== undefined && { min }),
    ...(max !== undefined && { max }),
    min_inclusive: mi,
    max_inclusive: xi,
  })),
  one_of: smallSet.map((values) => ({ constraint_type: "one_of", values })),
  not_one_of: smallSet.map((excluded) => ({ constraint_type: "not_one_of", excluded })),
  contains: smallSet.map((required) => ({ constraint_type: "contains", required })),
  subset: smallSet.map((allowed) => ({ constraint_type: "subset", allowed })),
  wildcard: fc.constant({ constraint_type: "wildcard" }),
};
const leafArb = fc.oneof(...Object.values(leafRaw));
const compositeArb = (inner: fc.Arbitrary<JsonValue>) =>
  fc.tuple(fc.constantFrom("all", "any"), fc.array(inner, { minLength: 1, maxLength: 3 })).map(([t, constraints]) => ({ constraint_type: t, constraints }) as JsonValue);
const anyArb = fc.oneof(leafArb, compositeArb(leafArb), compositeArb(compositeArb(leafArb)));
const parsed = (a: fc.Arbitrary<JsonValue>) => a.map(C);

const VALUES: JsonValue[] = [1, 2, 3, 4, -1, 0, 1.5, "a", "b", "c", true, false, null, [], [1], [1, 2], [2, 3], ["a"], ["a", "b"], [1, "a"], [1, 2, 3], { x: 1 }];

// ------------------------------------------------------------ property tests

test("subsumption is reflexive for every constraint type", () => {
  fc.assert(fc.property(parsed(anyArb), (c) => subsumes(c, c)));
});

test("subsumption is transitive (per type and mixed)", () => {
  for (const [name, arb] of [...Object.entries(leafRaw), ["composite", compositeArb(leafArb)], ["mixed", anyArb]] as const) {
    let checked = 0;
    fc.assert(
      fc.property(parsed(arb), parsed(arb), parsed(arb), (a, b, c) => {
        fc.pre(subsumes(a, b) && subsumes(b, c));
        checked++;
        assert.ok(subsumes(a, c), `${name}: ${JSON.stringify([a, b, c])}`);
      }),
      { numRuns: 4000, maxSkipsPerRun: 100000 },
    );
    assert.ok(checked > 0, `${name}: no triple exercised`);
  }
});

test("subsumption is sound: a value the child accepts, the parent accepts", () => {
  let related = 0;
  fc.assert(
    fc.property(parsed(anyArb), parsed(anyArb), (child, parent) => {
      fc.pre(subsumes(child, parent));
      related++;
      for (const v of VALUES) if (satisfies(child, v)) assert.ok(satisfies(parent, v), `${JSON.stringify(v)} ${JSON.stringify([child, parent])}`);
    }),
    { numRuns: 5000, maxSkipsPerRun: 100000 },
  );
  assert.ok(related > 100);
});

test("a wildcard parent is subsumed by every type; a wildcard child only by wildcard", () => {
  fc.assert(
    fc.property(parsed(anyArb), (c) => {
      assert.ok(subsumes(c, C({ constraint_type: "wildcard" })));
      if (c.type !== "wildcard") assert.ok(!subsumes(C({ constraint_type: "wildcard" }), c));
    }),
  );
});

// --------------------------------------------------------- named §4.5 rules

const exact = (value: JsonValue) => C({ constraint_type: "exact", value });
const oneOf = (values: JsonValue[]) => C({ constraint_type: "one_of", values });
const range = (o: Record<string, JsonValue>) => C({ constraint_type: "range", ...o });

test("§4.5 exact", () => {
  assert.ok(subsumes(exact("a"), exact("a")));
  assert.ok(!subsumes(exact("a"), exact("b")));
  assert.ok(!subsumes(exact(1), exact("1")));
  assert.ok(subsumes(exact(5), range({ min: 1, max: 10 })));
  assert.ok(!subsumes(exact(5), range({ min: 1, max: 5, max_inclusive: false })));
  assert.ok(!subsumes(exact("5"), range({ min: 1, max: 10 })));
  assert.ok(subsumes(exact("a"), oneOf(["a", "b"])));
  assert.ok(!subsumes(exact("c"), oneOf(["a", "b"])));
  // not named: rejected
  assert.ok(!subsumes(exact("a"), C({ constraint_type: "not_one_of", excluded: ["b"] })));
  assert.ok(!subsumes(exact("a"), C({ constraint_type: "any", constraints: [{ constraint_type: "exact", value: "a" }] })));
});

test("§4.5 range bounds and inclusivity", () => {
  assert.ok(subsumes(range({ min: 2, max: 8 }), range({ min: 1, max: 10 })));
  assert.ok(!subsumes(range({ min: 0, max: 8 }), range({ min: 1, max: 10 })));
  assert.ok(!subsumes(range({ min: 2 }), range({ min: 1, max: 10 }))); // missing derived max under a bounded parent
  assert.ok(subsumes(range({ min: 2, max: 8 }), range({ min: 1 }))); // missing parent max is unbounded
  assert.ok(subsumes(range({ min: 1, min_inclusive: false }), range({ min: 1 })));
  assert.ok(!subsumes(range({ min: 1 }), range({ min: 1, min_inclusive: false })));
  assert.ok(subsumes(range({ max: 1, max_inclusive: false }), range({ max: 1 })));
  assert.ok(!subsumes(range({ max: 1 }), range({ max: 1, max_inclusive: false })));
  assert.ok(subsumes(range({ min: 2, min_inclusive: true }), range({ min: 1, min_inclusive: false })));
});

test("§4.5 one_of, not_one_of, contains, subset", () => {
  assert.ok(subsumes(oneOf(["a"]), oneOf(["a", "b"])));
  assert.ok(!subsumes(oneOf(["a", "c"]), oneOf(["a", "b"])));
  assert.ok(!subsumes(C({ constraint_type: "not_one_of", excluded: ["x"] }), oneOf(["a", "b"]))); // MUST be rejected
  assert.ok(subsumes(C({ constraint_type: "not_one_of", excluded: ["x", "y"] }), C({ constraint_type: "not_one_of", excluded: ["x"] })));
  assert.ok(!subsumes(C({ constraint_type: "not_one_of", excluded: [] }), C({ constraint_type: "not_one_of", excluded: ["x"] })));
  assert.ok(subsumes(C({ constraint_type: "contains", required: [1, 2] }), C({ constraint_type: "contains", required: [1] })));
  assert.ok(!subsumes(C({ constraint_type: "contains", required: [] }), C({ constraint_type: "contains", required: [1] })));
  assert.ok(subsumes(C({ constraint_type: "subset", allowed: [1] }), C({ constraint_type: "subset", allowed: [1, 2] })));
  assert.ok(!subsumes(C({ constraint_type: "subset", allowed: [1, 2, 3] }), C({ constraint_type: "subset", allowed: [1, 2] })));
});

test("§4.5 all: one-to-one matching with backtracking, extra clauses allowed", () => {
  const all = (...cs: JsonValue[]) => C({ constraint_type: "all", constraints: cs });
  const ex = (v: JsonValue): JsonValue => ({ constraint_type: "exact", value: v });
  const one = (...v: JsonValue[]): JsonValue => ({ constraint_type: "one_of", values: v });
  assert.ok(subsumes(all(one(1), one(2)), all(one(1, 2), one(2, 3))));
  assert.ok(subsumes(all(one(1), one(2), ex(2)), all(one(1, 2))));
  assert.ok(!subsumes(all(one(1)), all(one(1), one(2)))); // a parent clause dropped
  // the single derived clause may not serve two parent clauses
  assert.ok(!subsumes(all(one(1)), all(one(1, 2), one(1, 3))));
  // greedy would assign one(1) to the first parent clause and fail on the second; backtracking succeeds
  assert.ok(subsumes(all(one(1), one(1, 2)), all(one(1, 2), one(1, 2, 3))));
  assert.ok(!subsumes(all(one(1)), C({ constraint_type: "any", constraints: [one(1)] }))); // `all` against `any`: not named
});

test("§4.5 any: every derived clause under some parent clause; clauses may be removed, not added", () => {
  const any = (...cs: JsonValue[]) => C({ constraint_type: "any", constraints: cs });
  const ex = (v: JsonValue): JsonValue => ({ constraint_type: "exact", value: v });
  assert.ok(subsumes(any(ex("pdf"), ex("csv")), any(ex("pdf"), ex("csv"), ex("xlsx"))));
  assert.ok(!subsumes(any(ex("pdf"), ex("docx")), any(ex("pdf"), ex("csv"), ex("xlsx"))));
  assert.ok(subsumes(any(ex("pdf")), any({ constraint_type: "one_of", values: ["pdf", "csv"] }))); // cross-type clause
  assert.equal((parseConstraint({ constraint_type: "any", constraints: [] }) as { kind: string }).kind, "malformed"); // §4.5: derived any MUST contain a clause
});

test("parse: unknown types fail closed, extra members and empty composites are malformed", () => {
  assert.deepEqual(parseConstraint({ constraint_type: "regex", pattern: "." }), { kind: "unknown_constraint", message: 'unrecognized constraint_type "regex"' });
  assert.equal((parseConstraint({ constraint_type: "exact", value: 1, extra: 1 }) as { kind: string }).kind, "malformed");
  assert.equal((parseConstraint({ constraint_type: "exact", value: null }) as { kind: string }).kind, "malformed");
  assert.equal((parseConstraint({ constraint_type: "all", constraints: [] }) as { kind: string }).kind, "malformed");
  assert.equal((parseConstraint({ constraint_type: "range", min: "1" }) as { kind: string }).kind, "malformed");
  assert.equal(constraintDepth(C({ constraint_type: "all", constraints: [{ constraint_type: "any", constraints: [{ constraint_type: "wildcard" }] }] })), 3);
});

// ----------------------------------------------------------- chain level (I4)

function opts(c: Chain, extra: Partial<VerifyOptions> = {}): VerifyOptions {
  return { trustAnchors: [{ alg: "EdDSA", publicKey: c.anchor.publicKey }], now: c.now, aat: { maxTokenLifetime: 1000 }, ...extra };
}

const rootTools: Tools = {
  read: { path: { constraint_type: "one_of", values: ["/a", "/b"] }, limit: { constraint_type: "range", max: 100 } },
  search: {},
};

function i4(linkTools: Tools | undefined) {
  const c = mintChain({ depth: 1, tools: rootTools, linkTools: [linkTools] });
  const r = verifyChain(c.compact, "aat-01", opts(c));
  return r.ok ? "accept" : `${r.code}:${r.check}`;
}

test("I4 at chain level: tools, closed-world key set, per-key subsumption", () => {
  assert.equal(i4(undefined), "accept");
  assert.equal(i4({ read: { path: { constraint_type: "exact", value: "/a" }, limit: { constraint_type: "range", max: 10 } } }), "accept"); // tool omitted + narrowed
  assert.equal(i4({}), "accept"); // empty capability set
  assert.equal(i4({ write: {} }), "I4:tools_subset");
  assert.equal(i4({ read: { path: { constraint_type: "exact", value: "/a" } } }), "I4:argument_keys_preserved"); // key dropped
  assert.equal(i4({ read: { path: { constraint_type: "exact", value: "/a" }, limit: { constraint_type: "range", max: 10 }, extra: { constraint_type: "wildcard" } } }), "I4:argument_keys_preserved");
  assert.equal(i4({ read: { path: { constraint_type: "one_of", values: ["/a", "/b", "/c"] }, limit: { constraint_type: "range", max: 10 } } }), "I4:constraint_subsumption");
  assert.equal(i4({ read: { path: { constraint_type: "wildcard" }, limit: { constraint_type: "range", max: 100 } } }), "I4:constraint_subsumption");
  assert.equal(i4({ read: { path: { constraint_type: "exact", value: "/a" }, limit: { constraint_type: "range", max: 101 } } }), "I4:constraint_subsumption");
  // open-world parent: the child may introduce keys
  assert.equal(i4({ search: { query: { constraint_type: "exact", value: "q" } } }), "accept");
  // draft-named cross-type pair that must be rejected
  assert.equal(i4({ read: { path: { constraint_type: "not_one_of", excluded: ["/c"] }, limit: { constraint_type: "range", max: 10 } } }), "I4:constraint_subsumption");
});

test("I4 in the middle of a longer chain: an empty-capability intermediate can only derive empty tokens", () => {
  const c = mintChain({ depth: 2, tools: rootTools, linkTools: [{}, { read: {} }] });
  const r = verifyChain(c.compact, "aat-01", opts(c));
  assert.ok(!r.ok);
  assert.equal(r.code, "I4");
});

test("unknown constraint type denies; deep constraint tree denies", () => {
  const c = mintChain({ depth: 0, tools: { t: { a: { constraint_type: "regex", pattern: "." } } } });
  const r = verifyChain(c.compact, "aat-01", opts(c));
  assert.ok(!r.ok);
  assert.equal(r.code, "unknown_constraint");
  let deep: JsonValue = { constraint_type: "wildcard" };
  for (let i = 0; i < 3; i++) deep = { constraint_type: "all", constraints: [deep] };
  const d = mintChain({ depth: 0, tools: { t: { a: deep } } });
  const ok = verifyChain(d.compact, "aat-01", opts(d));
  assert.ok(ok.ok);
  const rr = verifyChain(d.compact, "aat-01", opts(d, { aat: { maxTokenLifetime: 1000, maxConstraintDepth: 3 } }));
  assert.ok(!rr.ok);
  assert.equal(rr.code, "constraint_depth");
});

test("property: narrowing keeps acceptance, widening is rejected (same-type pairs)", () => {
  const pairs = fc.constantFrom<[JsonValue, JsonValue, JsonValue]>(
    [{ constraint_type: "exact", value: 3 }, { constraint_type: "range", min: 1, max: 5 }, { constraint_type: "range", min: 0, max: 5 }],
    [{ constraint_type: "one_of", values: [1] }, { constraint_type: "one_of", values: [1, 2] }, { constraint_type: "one_of", values: [1, 2, 3] }],
    [{ constraint_type: "not_one_of", excluded: [1, 2] }, { constraint_type: "not_one_of", excluded: [1] }, { constraint_type: "not_one_of", excluded: [] }],
    [{ constraint_type: "contains", required: [1, 2] }, { constraint_type: "contains", required: [1] }, { constraint_type: "contains", required: [] }],
    [{ constraint_type: "subset", allowed: [1] }, { constraint_type: "subset", allowed: [1, 2] }, { constraint_type: "subset", allowed: [1, 2, 3] }],
    [{ constraint_type: "range", min: 2, max: 3 }, { constraint_type: "range", min: 1, max: 4 }, { constraint_type: "range", max: 4 }],
    [{ constraint_type: "exact", value: "a" }, { constraint_type: "wildcard" }, { constraint_type: "wildcard" }],
  );
  fc.assert(
    fc.property(pairs, fc.integer({ min: 1, max: 4 }), ([narrow, mid, wide], depth) => {
      // root carries `mid`; the last link narrows (accept) or widens to `wide` (reject)
      const mk = (leaf: JsonValue) => {
        const linkTools: (Tools | undefined)[] = Array.from({ length: depth }, (_, i) => (i === depth - 1 ? { t: { a: leaf } } : undefined));
        return mintChain({ depth, tools: { t: { a: mid } }, linkTools });
      };
      const ok = mk(narrow);
      assert.ok(verifyChain(ok.compact, "aat-01", opts(ok)).ok);
      if (JSON.stringify(wide) !== JSON.stringify(mid)) {
        const bad = mk(wide);
        const r = verifyChain(bad.compact, "aat-01", opts(bad));
        assert.ok(!r.ok);
        assert.equal(r.code, "I4");
      }
    }),
    { numRuns: 50 },
  );
});

// ------------------------------------------------------------------- I6 (PoP)

const leafTools: Tools = { read: { path: { constraint_type: "exact", value: "/a" }, mode: { constraint_type: "wildcard" } }, ping: {} };

function popCase(over: { tool?: string; args?: Record<string, unknown>; popTool?: string; popArgs?: JsonValue; aatId?: string; iat?: number; signer?: ReturnType<typeof newHolder>; aud?: string; nonCanonical?: boolean; alg?: string }, extra: Partial<VerifyOptions> = {}) {
  const c = mintChain({ depth: 2, tools: leafTools });
  const tool = over.tool ?? "read";
  const args = over.args ?? { path: "/a", mode: "r" };
  const pop = mintPop({
    holder: over.signer ?? c.leaf.holder,
    aatId: over.aatId ?? (c.leaf.claims.jti as string),
    tool: over.popTool ?? tool,
    args: over.popArgs ?? (args as JsonValue),
    iat: over.iat ?? c.now,
    ...(over.aud !== undefined && { aud: over.aud }),
    ...(over.nonCanonical && { nonCanonical: true }),
  });
  const r = verifyChain(c.compact, "aat-01", opts(c, { request: { aat: { tool, args, pop } }, ...extra }));
  return r.ok ? "accept" : `${r.code}:${r.check}`;
}

test("I6: a correct PoP is accepted; mismatches are rejected with I6", () => {
  assert.equal(popCase({}), "accept");
  assert.equal(popCase({ popTool: "ping" }), "I6:pop_tool");
  assert.equal(popCase({ popArgs: { path: "/a", mode: "w" } }), "I6:pop_args");
  assert.equal(popCase({ aatId: "00000000-0000-4000-8000-000000000000" }), "I6:pop_aat_id");
  assert.equal(popCase({ iat: 1_000_031 }), "I6:pop_iat");
  assert.equal(popCase({ iat: 999_969 }), "I6:pop_iat");
  assert.equal(popCase({ iat: 1_000_030 }), "accept");
  assert.equal(popCase({ nonCanonical: true }), "I6:pop_claims");
});

test("I6: PoP signed by a key other than leaf.cnf.jwk, including the parent's, is rejected", () => {
  assert.equal(popCase({ signer: newHolder() }), "I6:pop_signature");
  const c = mintChain({ depth: 2, tools: leafTools });
  const parentHolder = c.tokens[1]!.holder; // holds the parent token; its key signed the leaf, not the PoP
  const args = { path: "/a", mode: "r" };
  const pop = mintPop({ holder: parentHolder, aatId: c.leaf.claims.jti as string, tool: "read", args, iat: c.now });
  const r = verifyChain(c.compact, "aat-01", opts(c, { request: { aat: { tool: "read", args, pop } } }));
  assert.ok(!r.ok);
  assert.equal(r.code, "I6");
  assert.equal(r.check, "pop_signature");
});

test("I6: PoP alg none or off the allowlist; audience binding when required", () => {
  const c = mintChain({ depth: 0, tools: leafTools });
  const args = { path: "/a", mode: "r" };
  const good = mintPop({ holder: c.leaf.holder, aatId: c.leaf.claims.jti as string, tool: "read", args, iat: c.now, aud: "https://tools.example.com" });
  const run = (pop: string, aat?: VerifyOptions["aat"]) => {
    const r = verifyChain(c.compact, "aat-01", opts(c, { request: { aat: { tool: "read", args, pop } }, ...(aat && { aat }) }));
    return r.ok ? "accept" : `${r.code}:${r.check}`;
  };
  assert.equal(run(good), "accept");
  assert.equal(run(good, { maxTokenLifetime: 1000, popAudience: "https://tools.example.com" }), "accept");
  assert.equal(run(good, { maxTokenLifetime: 1000, popAudience: "https://other.example.com" }), "I6:pop_audience");
  const noAud = mintPop({ holder: c.leaf.holder, aatId: c.leaf.claims.jti as string, tool: "read", args, iat: c.now });
  assert.equal(run(noAud, { maxTokenLifetime: 1000, popAudience: "https://tools.example.com" }), "I6:pop_audience");
  const [, p] = good.split(".");
  assert.equal(run(`${Buffer.from('{"alg":"none"}').toString("base64url")}.${p}.`), "I6:pop_alg");
  assert.equal(run(`${Buffer.from('{"alg":"ES256"}').toString("base64url")}.${p}.AAAA`), "I6:pop_alg");
});

test("step 6b: closed world, missing constrained argument, violated constraint, unlisted tool", () => {
  const c = mintChain({ depth: 1, tools: leafTools });
  const run = (tool: string, args: Record<string, unknown>) => {
    const pop = mintPop({ holder: c.leaf.holder, aatId: c.leaf.claims.jti as string, tool, args: args as JsonValue, iat: c.now });
    const r = verifyChain(c.compact, "aat-01", opts(c, { request: { aat: { tool, args, pop } } }));
    return r.ok ? "accept" : `${r.code}:${r.check}`;
  };
  assert.equal(run("read", { path: "/a", mode: "r" }), "accept");
  assert.equal(run("read", { path: "/a", mode: "r", extra: 1 }), "authorization_denied:leaf_arguments");
  assert.equal(run("read", { path: "/a" }), "authorization_denied:leaf_arguments");
  assert.equal(run("read", { path: "/b", mode: "r" }), "authorization_denied:leaf_arguments");
  assert.equal(run("write", {}), "authorization_denied:leaf_arguments");
  assert.equal(run("ping", { anything: 1 }), "accept"); // empty constraint map: open world
  assert.equal(run("__proto__", {}), "authorization_denied:leaf_arguments");
});

test("PoP is only evaluated after the chain verified", () => {
  const c = mintChain({ depth: 1, tools: leafTools });
  const args = { path: "/a", mode: "r" };
  const pop = mintPop({ holder: c.leaf.holder, aatId: c.leaf.claims.jti as string, tool: "read", args, iat: c.now });
  const r = verifyChain([c.compact[0]!, c.compact[1]!.slice(0, -2) + "AA"], "aat-01", opts(c, { request: { aat: { tool: "read", args, pop } } }));
  assert.ok(!r.ok);
  assert.equal(r.code, "signature_invalid");
});
