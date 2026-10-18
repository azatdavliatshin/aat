/**
 * Generator for vectors/aat/*.json: our own AAT-01 test vectors, derived from
 * our reading of draft-niyikiza-oauth-attenuating-agent-tokens-01. Fully
 * deterministic: fixed seed keys, fixed timestamps, fixed jti values (Ed25519
 * signatures are deterministic). Run: npm run vectors:aat
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { thumbprintUri } from "../profiles/aat01.js";
import type { JsonObject, JsonValue } from "../json.js";
import { derive, holderFromSeed, mintChain, mintPop, mintRoot, type Chain, type Holder, type Override, type Tools } from "./aat-mint.js";

export interface AatVector {
  name: string;
  description: string;
  draft: "01";
  /** Verification time (NumericDate). */
  now: number;
  /** Public JWKs of the trusted root issuers. */
  trust_anchors: JsonObject[];
  /** Root-first compact JWS. */
  chain: string[];
  /** Present when steps 6 and 7 are exercised. */
  request?: { tool: string; args: JsonObject };
  pop?: string;
  /** Verifier options that differ from the defaults (maxTokenLifetime is always set). */
  options: Record<string, JsonValue>;
  expect: { outcome: "accept" } | { outcome: "reject"; code: string; check: string };
}

const NOW = 1_800_000_000;
const seed = (n: number) => holderFromSeed(n.toString(16).padStart(64, "0"));
const ANCHOR = seed(1);
const HOLDERS: Holder[] = [2, 3, 4, 5, 6].map(seed);
const STRANGER = seed(15);
const jti = (n: number) => `01957a3f-4e23-7b01-a9d1-0050569c2e${n.toString(16).padStart(2, "0")}`;
const OPTIONS = { maxTokenLifetime: 1000 };

const base = (tools: Tools, depth: number, extra: Partial<Parameters<typeof mintChain>[0]> = {}): Chain =>
  mintChain({ depth, now: NOW, tools, anchor: ANCHOR, holders: HOLDERS, jtis: [0, 1, 2, 3, 4, 5].map((i) => jti(i + 1)), maxDepth: Math.max(depth, 3), ...extra });

const TOOLS: Tools = { read: { path: { constraint_type: "one_of", values: ["/data/a", "/data/b"] }, limit: { constraint_type: "range", max: 100 } }, ping: {} };
const ARGS = { path: "/data/a", limit: 10 };

function vec(name: string, description: string, c: Chain, expect: AatVector["expect"], o: { chain?: string[]; pop?: string | true; args?: JsonObject; tool?: string; options?: Record<string, JsonValue> } = {}): AatVector {
  const tool = o.tool ?? "read";
  const args = o.args ?? ARGS;
  const pop = o.pop === true ? mintPop({ holder: c.leaf.holder, aatId: c.leaf.claims.jti as string, tool, args, iat: NOW, jti: "c980f2a1-4a37-4e88-bb3c-9defd37c1a45" }) : o.pop;
  return {
    name, description, draft: "01", now: NOW,
    trust_anchors: [ANCHOR.jwk], chain: o.chain ?? c.compact,
    ...(pop !== undefined && { request: { tool, args }, pop }),
    options: { ...OPTIONS, ...o.options }, expect,
  };
}

const accept = { outcome: "accept" } as const;
const reject = (code: string, check: string) => ({ outcome: "reject", code, check }) as const;

/** The last link replaced by a child of its parent with the given overrides. */
function lastLink(c: Chain, spec: Partial<Parameters<typeof derive>[0]>): string[] {
  const parent = c.tokens[c.tokens.length - 2] as Chain["tokens"][number];
  const bad = derive({ parent, iat: c.leaf.claims.iat as number, exp: c.leaf.claims.exp as number, jti: c.leaf.claims.jti as string, holder: c.leaf.holder, ...spec });
  return [...c.compact.slice(0, -1), bad.compact];
}

type Pair = { parent: JsonValue; narrow: JsonValue; widen: JsonValue; note: string };
const ex = (value: JsonValue): JsonValue => ({ constraint_type: "exact", value });
const rng = (o: JsonObject): JsonValue => ({ constraint_type: "range", ...o });
const one = (...values: JsonValue[]): JsonValue => ({ constraint_type: "one_of", values });
const PAIRS: Record<string, Pair> = {
  exact: { parent: rng({ min: 1, max: 10 }), narrow: ex(5), widen: ex(11), note: "exact inside a parent range / outside it" },
  range: { parent: rng({ min: 1, max: 10 }), narrow: rng({ min: 2, max: 5 }), widen: rng({ min: 0, max: 10 }), note: "bounds tightened / lower bound lowered" },
  one_of: { parent: one("a", "b"), narrow: one("a"), widen: one("a", "b", "c"), note: "value set shrunk / grown" },
  not_one_of: { parent: { constraint_type: "not_one_of", excluded: ["x"] }, narrow: { constraint_type: "not_one_of", excluded: ["x", "y"] }, widen: { constraint_type: "not_one_of", excluded: [] }, note: "exclusion added / removed" },
  contains: { parent: { constraint_type: "contains", required: [1] }, narrow: { constraint_type: "contains", required: [1, 2] }, widen: { constraint_type: "contains", required: [] }, note: "requirement added / removed" },
  subset: { parent: { constraint_type: "subset", allowed: [1, 2] }, narrow: { constraint_type: "subset", allowed: [1] }, widen: { constraint_type: "subset", allowed: [1, 2, 3] }, note: "allowed set shrunk / grown" },
  wildcard: { parent: { constraint_type: "wildcard" }, narrow: ex("a"), widen: { constraint_type: "wildcard" }, note: "wildcard narrowed to exact; the widening case is exact -> wildcard (see below)" },
  all: { parent: { constraint_type: "all", constraints: [one(1, 2), rng({ max: 10 })] }, narrow: { constraint_type: "all", constraints: [one(1), rng({ max: 5 }), ex(1)] }, widen: { constraint_type: "all", constraints: [one(1, 2)] }, note: "clauses narrowed and one added / a parent clause dropped" },
  any: { parent: { constraint_type: "any", constraints: [ex("a"), ex("b"), ex("c")] }, narrow: { constraint_type: "any", constraints: [ex("a"), ex("b")] }, widen: { constraint_type: "any", constraints: [ex("a"), ex("d")] }, note: "clause removed / a clause outside the parent's" },
};

export function buildVectors(): AatVector[] {
  const out: AatVector[] = [];

  // One valid chain per depth 0..3, each with a PoP over the leaf.
  for (let d = 0; d <= 3; d++) {
    const c = base(TOOLS, d);
    out.push(vec(`valid_depth_${d}`, `A valid chain of ${d + 1} token(s) with a PoP over tool read.`, c, accept, { pop: true }));
  }

  // I1
  {
    const c = base(TOOLS, 2);
    out.push(vec("reject_i1_iss_not_parent_holder", "Leaf iss is the thumbprint URI of a key that is not the parent's cnf.jwk (signed by the right key).", c, reject("I1", "delegation_authority"), { chain: lastLink(c, { override: { iss: thumbprintUri(STRANGER.jwk) } }) }));
    out.push(vec("reject_signature_wrong_parent_key", "Leaf is signed by a key other than the parent's cnf.jwk, with iss naming that key.", c, reject("signature_invalid", "signature"), { chain: lastLink(c, { signer: STRANGER }) }));
  }
  // I2
  {
    const c = base(TOOLS, 2, { maxDepth: 4 });
    out.push(vec("reject_i2_depth_skipped", "Leaf del_depth is parent + 2.", c, reject("I2", "depth_increment"), { chain: lastLink(c, { override: { del_depth: 4 } }) }));
    out.push(vec("reject_i2_max_depth_raised", "Leaf del_max_depth exceeds the parent's.", c, reject("I2", "max_depth_not_raised"), { chain: lastLink(c, { override: { del_max_depth: 5 } }) }));
  }
  // I3
  {
    const c = base(TOOLS, 2);
    const p = c.tokens[1] as Chain["tokens"][number];
    out.push(vec("reject_i3_exp_exceeds_parent", "Leaf exp is one second past the parent's.", c, reject("I3", "exp_le_parent"), { chain: lastLink(c, { override: { iat: (p.claims.iat as number) + 1, exp: (p.claims.exp as number) + 1 } }) }));
    out.push(vec("reject_i3_iat_before_parent", "Leaf iat precedes the parent's.", c, reject("I3", "iat_ge_parent"), { chain: lastLink(c, { override: { iat: (p.claims.iat as number) - 1 } }) }));
    out.push(vec("reject_i3_expired", "Leaf exp equals now.", c, reject("I3", "exp_after_now"), { chain: lastLink(c, { override: { exp: NOW } }) }));
  }
  // I4
  {
    const added = base(TOOLS, 1, { linkTools: [{ write: {} }] });
    out.push(vec("reject_i4_tool_added", "Child authorizes a tool the parent did not.", added, reject("I4", "tools_subset")));
    const dropped = base(TOOLS, 1, { linkTools: [{ read: { path: ex("/data/a") } }] });
    out.push(vec("reject_i4_argument_key_dropped", "Child drops the limit constraint from a constrained tool (closed world: the key set must be preserved).", dropped, reject("I4", "argument_keys_preserved")));
    const cross = base(TOOLS, 1, { linkTools: [{ read: { path: { constraint_type: "not_one_of", excluded: ["/etc/passwd"] }, limit: rng({ max: 100 }) } }] });
    out.push(vec("reject_i4_not_one_of_over_one_of", "Child replaces a parent one_of by a not_one_of (§4.5: MUST be rejected).", cross, reject("I4", "constraint_subsumption")));
  }
  // I5
  {
    const c = base(TOOLS, 2);
    const other = mintRoot({ anchor: ANCHOR, iat: NOW - 100, exp: NOW + 500, jti: jti(0x20), tools: TOOLS, holder: HOLDERS[1] as Holder });
    out.push(vec("reject_i5_par_hash_other_parent", "Leaf par_hash commits to a different token than the parent presented.", c, reject("I5", "par_hash"), { chain: lastLink(c, { parHashOf: other.compact }) }));
  }
  // I6 (PoP)
  {
    const c = base(TOOLS, 2);
    const mk = (o: Partial<Parameters<typeof mintPop>[0]>) => mintPop({ holder: c.leaf.holder, aatId: c.leaf.claims.jti as string, tool: "read", args: ARGS, iat: NOW, jti: "c980f2a1-4a37-4e88-bb3c-9defd37c1a46", ...o });
    out.push(vec("reject_i6_pop_other_tool", "PoP names tool ping, the invocation is read.", c, reject("I6", "pop_tool"), { pop: mk({ tool: "ping" }) }));
    out.push(vec("reject_i6_pop_other_args", "PoP hta differs from the invocation arguments.", c, reject("I6", "pop_args"), { pop: mk({ args: { path: "/data/b", limit: 10 } }) }));
    out.push(vec("reject_i6_pop_other_token", "PoP aat_id is not the leaf jti.", c, reject("I6", "pop_aat_id"), { pop: mk({ aatId: jti(0x30) }) }));
    out.push(vec("reject_i6_pop_signed_by_parent", "PoP is signed by the parent's holder key, not the leaf's.", c, reject("I6", "pop_signature"), { pop: mk({ holder: c.tokens[1]!.holder }) }));
    out.push(vec("reject_i6_pop_replayed", "PoP iat is 31 s before now, outside the +-30 s window.", c, reject("I6", "pop_iat"), { pop: mk({ iat: NOW - 31 }) }));
  }
  // Leaf closed-world
  {
    const c = base(TOOLS, 1);
    out.push(vec("reject_leaf_unlisted_argument", "Invocation carries an argument the constraint map does not name (step 6b).", c, reject("authorization_denied", "leaf_arguments"), { pop: true, args: { ...ARGS, extra: 1 } }));
  }
  // alg none, jti cycle
  {
    const c = base(TOOLS, 1);
    const [, payload] = (c.compact[0] as string).split(".");
    const none = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${payload}.`;
    out.push(vec("reject_alg_none_root", "Root token with alg none.", c, reject("signature_invalid", "jws_parse"), { chain: [none, c.compact[1] as string] }));
    const cycle = base(TOOLS, 2, { jtis: [jti(1), jti(2), jti(1)] });
    out.push(vec("reject_jti_cycle", "Leaf jti equals the root jti (token-instance cycle).", cycle, reject("jti_cycle", "jti_unique")));
  }
  // One narrowing (accept) and one widening (reject) per constraint type.
  for (const [type, pair] of Object.entries(PAIRS)) {
    const tools = (leaf: JsonValue): Tools => ({ t: { a: leaf } });
    const narrow = base(tools(pair.parent), 1, { linkTools: [tools(pair.narrow)] });
    out.push(vec(`accept_narrow_${type}`, `${type}: ${pair.note}. Narrowing is valid attenuation.`, narrow, accept));
    const widenChild = type === "wildcard" ? { parent: ex("a"), widen: pair.parent } : { parent: pair.parent, widen: pair.widen };
    const widen = base(tools(widenChild.parent), 1, { linkTools: [tools(widenChild.widen)] });
    out.push(vec(`reject_widen_${type}`, `${type}: widening is rejected by I4.`, widen, reject("I4", "constraint_subsumption")));
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = new URL("../../vectors/aat/", import.meta.url);
  mkdirSync(dir, { recursive: true });
  const vs = buildVectors();
  for (const v of vs) writeFileSync(new URL(`${v.name}.json`, dir), JSON.stringify(v, null, 2) + "\n");
  console.log(`wrote ${vs.length} vectors`);
}

export type { Override };
