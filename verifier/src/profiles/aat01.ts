import { createPublicKey, timingSafeEqual, type KeyObject } from "node:crypto";
import { fail, type Failure, type Outcome } from "../result.js";
import { isObject, parseJson, type JsonObject, type JsonValue } from "../json.js";
import { parentHash } from "../hash.js";
import { okpThumbprint } from "../holder.js";
import { verifyJws, type ParsedJws } from "../jws.js";
import type { Check, CheckResult, ChainContext, Node, Profile, VerifyOptions } from "../chain.js";
import { constraintDepth, parseConstraint, subsumes, type Constraint } from "./aat01-constraints.js";
import { authorizeInvocation, popChecks } from "./aat01-pop.js";

/**
 * draft-niyikiza-oauth-attenuating-agent-tokens-01. Section tags: "§n" are
 * sections of that draft; "step 4q" is a step of its §7 algorithm.
 *
 * Checks carry the draft's step number; `seq` orders the lettered sub-steps,
 * and for the per-pair step 4 it is pair-major (`child index * 100 + letter`)
 * so that all of pair k runs before pair k+1, as the draft's loop does.
 *
 * Failure codes: `I1`..`I6` are the invariants of §4; the others name the
 * class of the failed check (see the README).
 */

/** Limits and policy of §4.3, §4.3.1, §4.4, §3.4, §5.3; the draft recommends the defaults where it gives one. */
export interface AatOptions {
  /** MAX_DELEGATION_DEPTH (§4.3). The draft fixes no value; default 16. */
  maxDelegationDepth?: number;
  /** MAX_IAT_SKEW, seconds (§4.4). Default 30. */
  maxIatSkew?: number;
  /** MAX_TOKEN_LIFETIME, seconds (§4.4). Default 90 days. */
  maxTokenLifetime?: number;
  /** MAX_CONSTRAINT_DEPTH (§3.4). Default 32. */
  maxConstraintDepth?: number;
  /** MAX_TOKEN_SIZE, bytes (§4.3.1). Default 65536. */
  maxTokenSize?: number;
  /** MAX_STACK_SIZE, bytes (§4.3.1). Default 262144. */
  maxStackSize?: number;
  /** PoP `iat` tolerance, seconds either side of `now` (§5.3). Default 30. */
  popSkew?: number;
  /** Deployment policy "PoP audience binding" (§5.3 item 3, step 7d): the identifier of this enforcement point. */
  popAudience?: string;
  /** Reject a token that carries `sub` (§3.2 "intentionally omits"). Default true; see draft-observations. */
  rejectSub?: boolean;
}

export const AAT_DEFAULTS = {
  maxDelegationDepth: 16,
  maxIatSkew: 30,
  maxTokenLifetime: 90 * 24 * 3600,
  maxConstraintDepth: 32,
  maxTokenSize: 65536,
  maxStackSize: 262144,
  popSkew: 30,
  rejectSub: true,
} as const;

export function limits(opts: VerifyOptions): Required<Omit<AatOptions, "popAudience">> & { popAudience?: string } {
  return { ...AAT_DEFAULTS, ...opts.aat } as Required<Omit<AatOptions, "popAudience">> & { popAudience?: string };
}

export type ToolMap = ReadonlyMap<string, ReadonlyMap<string, Constraint>>;

export interface Aat01Token {
  claims: JsonObject;
  jti: string;
  iss: string;
  iat: number;
  exp: number;
  delDepth: number;
  delMaxDepth: number;
  parHash?: string;
  /** `cnf.jwk`, a public OKP Ed25519 key. */
  jwk: JsonObject;
  key: KeyObject;
  /** Number of `authorization_details` entries of type `attenuating_agent_token`. */
  entryCount: number;
  /** The `tools` map of the single entry; empty when there is no entry (the empty capability set, step 4n). */
  tools: ToolMap;
}

export const AAT_TYPE = "attenuating_agent_token";
export const THUMBPRINT_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

/** RFC 9278 JWK Thumbprint URI of a public OKP key (SHA-256). */
export function thumbprintUri(jwk: JsonObject): string {
  return THUMBPRINT_PREFIX + okpThumbprint(jwk);
}

const SEC_CLAIMS = "AAT-01 §3.2";
const bad = (section: string, message: string): Failure => fail("malformed", section, message);
const isNonNegInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** §3.2 / §3.3 / §3.4: what a verifier decides from the claims of one token. */
function parse(jws: ParsedJws): Outcome<Aat01Token> {
  const parsed = parseJson(jws.payloadBytes, SEC_CLAIMS);
  if (!parsed.ok) return parsed;
  const p = parsed.value;
  if (!isObject(p)) return bad(SEC_CLAIMS, "payload must be a JSON object");

  // §3.2 jti: non-empty string (step 3j, 4b1); a UUID MUST be lowercase hyphenated.
  if (typeof p.jti !== "string" || p.jti === "") return bad(SEC_CLAIMS, "jti is required, a non-empty string");
  // draft unspecified: whether a non-UUID jti is acceptable; §3.2 says SHOULD be UUIDv7, step 3j only asks non-empty.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(p.jti) && !UUID_SHAPE.test(p.jti)) {
    return bad(SEC_CLAIMS, "a UUID jti MUST be lowercase hyphenated");
  }
  if (typeof p.iss !== "string" || p.iss === "") return bad(SEC_CLAIMS, "iss is required, a non-empty string");
  for (const c of ["iat", "exp"] as const) {
    if (typeof p[c] !== "number") return bad(SEC_CLAIMS, `${c} is required, a NumericDate`);
  }
  if (!isNonNegInt(p.del_depth)) return bad(SEC_CLAIMS, "del_depth is required, a non-negative integer");
  if (!isNonNegInt(p.del_max_depth)) return bad(SEC_CLAIMS, "del_max_depth is required, a non-negative integer");
  if (p.par_hash !== undefined && typeof p.par_hash !== "string") return bad(SEC_CLAIMS, "par_hash must be a string");

  // §3.2 cnf: contains jwk, a public key. Ed25519 (OKP) only in this verifier; Ed448 and the other key types are not implemented.
  const cnf = p.cnf;
  if (!isObject(cnf) || !isObject(cnf.jwk)) return bad(SEC_CLAIMS, "cnf must be an object containing jwk");
  const jwk = cnf.jwk;
  if ("d" in jwk) return bad(SEC_CLAIMS, "cnf.jwk carries private key material");
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    return bad(SEC_CLAIMS, "cnf.jwk must be an OKP Ed25519 public key");
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  } catch {
    return bad(SEC_CLAIMS, "cnf.jwk is not a valid Ed25519 public key");
  }

  // §3.3: authorization_details is an array of objects with a `type`; entries of other types are ignored.
  const details = p.authorization_details;
  if (!Array.isArray(details)) return bad("AAT-01 §3.3", "authorization_details is required, an array");
  const entries: JsonObject[] = [];
  for (const d of details) {
    if (!isObject(d) || typeof d.type !== "string") return bad("AAT-01 §3.3", "each authorization_details entry needs a string type");
    if (d.type === AAT_TYPE) entries.push(d);
  }
  let tools: ToolMap = new Map();
  // More than one entry is a deny at the step that owns the count (3m, 4n, 6a); its tools are not parsed.
  if (entries.length === 1) {
    const t = parseTools((entries[0] as JsonObject).tools);
    if ("ok" in t) return t;
    tools = t;
  }
  return {
    ok: true,
    value: {
      claims: p,
      jti: p.jti,
      iss: p.iss,
      iat: p.iat as number,
      exp: p.exp as number,
      delDepth: p.del_depth,
      delMaxDepth: p.del_max_depth,
      ...(p.par_hash !== undefined && { parHash: p.par_hash as string }),
      jwk,
      key,
      entryCount: entries.length,
      tools,
    },
  };
}

/** §3.3: `tools` maps tool names to argument-name -> constraint maps. */
function parseTools(raw: JsonValue | undefined): ToolMap | Failure {
  if (!isObject(raw)) return bad("AAT-01 §3.3", "an attenuating_agent_token entry MUST include a tools object");
  const tools = new Map<string, ReadonlyMap<string, Constraint>>();
  for (const [tool, args] of Object.entries(raw)) {
    if (!isObject(args)) return bad("AAT-01 §3.3", `tool ${JSON.stringify(tool)}: the constraint set must be an object`);
    const map = new Map<string, Constraint>();
    for (const [arg, rawConstraint] of Object.entries(args)) {
      const c = parseConstraint(rawConstraint);
      if ("kind" in c) return fail(c.kind === "unknown_constraint" ? "unknown_constraint" : "malformed", "AAT-01 §3.4", `${tool}.${arg}: ${c.message}`);
      map.set(arg, c);
    }
    tools.set(tool, map);
  }
  return tools;
}

type T = Aat01Token;
type N = Node<T>;
const deny = (code: string, section: string, message: string): CheckResult => ({ code, section, message });

/** Letters of the §7 step 4 sub-steps as sequence numbers. */
const L = { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7, h: 8, i: 9, j: 10, k: 11, l: 12, m: 13, n: 14, o: 15, p: 16, q: 17 } as const;

function equal(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

/** §7 steps 2a and 2b, before any parsing; step 1 (empty chain). */
function preflight(tokens: readonly string[], opts: VerifyOptions): Failure | undefined {
  if (tokens.length === 0) return fail("chain_empty", "AAT-01 §7 step 1", "the chain is empty", { check: "chain_not_empty" });
  const lim = limits(opts);
  let total = 0;
  for (const [i, t] of tokens.entries()) {
    const size = Buffer.byteLength(t, "utf8");
    total += size;
    if (size > lim.maxTokenSize) return fail("size_limit", "AAT-01 §4.3.1, §7 step 2a", `token exceeds MAX_TOKEN_SIZE ${lim.maxTokenSize}`, { token: i, check: "token_size" });
  }
  if (total > lim.maxStackSize) return fail("size_limit", "AAT-01 §4.3.1, §7 step 2b", `chain exceeds MAX_STACK_SIZE ${lim.maxStackSize}`, { check: "stack_size" });
  return undefined;
}

/** Steps 3a/3b and 4a/4b (signature), step 4q (I5). Replaces the generic shared checks. */
function sharedChecks(chain: readonly N[], opts: VerifyOptions): Check[] {
  const accepted = opts.acceptedAlgs ?? ["EdDSA"];
  const out: Check[] = [];
  for (const node of chain) {
    const step = node.index === 0 ? 3 : 4;
    const base = node.index === 0 ? 0 : node.index * 100;
    const where = node.index === 0 ? "step 3" : "step 4";
    out.push({
      name: "alg_allowed", step, seq: base + L.a, token: node.index,
      run() {
        // §8.13: HS256 and the other symmetric algorithms MUST NOT be used for AAT signatures; every key here is Ed25519.
        if (node.jws.alg !== "EdDSA" || !accepted.includes("EdDSA") || !accepted.includes(node.jws.alg)) {
          return deny("signature_invalid", `AAT-01 §7 ${where}a, §8.13`, `alg ${node.jws.alg} is not permitted or does not fit the verifying key`);
        }
        return undefined;
      },
    });
    out.push({
      name: "signature", step, seq: base + L.b, token: node.index,
      run() {
        if (node.index === 0) {
          const anchors = (opts.trustAnchors ?? []).filter((a) => a.alg === "EdDSA");
          return anchors.some((a) => verifyJws(node.jws, a)) ? undefined : deny("signature_invalid", "AAT-01 §7 step 3b", "root signature does not verify under any trust anchor");
        }
        const parent = chain[node.index - 1] as N;
        return verifyJws(node.jws, { alg: "EdDSA", publicKey: parent.claims.key })
          ? undefined
          : deny("signature_invalid", "AAT-01 §7 step 4b, §4.2", "signature does not verify under the parent's cnf.jwk");
      },
    });
  }
  for (const child of chain.slice(1)) {
    const parent = chain[child.index - 1] as N;
    out.push({
      name: "par_hash_present", step: 4, seq: child.index * 100 + L.b, token: child.index,
      run: () => child.claims.parHash === undefined ? deny("malformed", "AAT-01 §3.2, §7 step 4b5", "par_hash is REQUIRED in derived tokens") : undefined,
    });
    out.push({
      name: "par_hash", step: 4, seq: child.index * 100 + L.q, token: child.index,
      run: () => equal(child.claims.parHash ?? "", parentHash(parent.jws.compact)) ? undefined : deny("I5", "AAT-01 §4.6, §7 step 4q", "par_hash does not equal SHA-256 of the parent signing input"),
    });
  }
  return out;
}

/** The six I3 inequalities (§4.4) as one named check per inequality. */
function timeChecks(n: N, parent: N | undefined, ctx: ChainContext<T>): Check[] {
  const { now } = ctx.options;
  const lim = limits(ctx.options);
  const step = parent ? 4 : 3;
  const base = parent ? n.index * 100 : 0;
  const sec = (letter: string) => `AAT-01 §4.4, §7 step ${step}${letter}`;
  const t = n.claims;
  const mk = (name: string, seq: number, letter: string, ok: () => boolean, message: string): Check => ({
    name, step, seq: base + seq, token: n.index, run: () => ok() ? undefined : deny("I3", sec(letter), message),
  });
  return [
    ...(parent ? [mk("exp_le_parent", L.h, "h", () => t.exp <= parent.claims.exp, "exp exceeds the parent's exp")] : []),
    mk("exp_after_now", L.i, parent ? "i" : "e", () => t.exp > now, "token has expired"),
    ...(parent ? [mk("iat_ge_parent", L.j, "j", () => t.iat >= parent.claims.iat, "iat precedes the parent's iat")] : []),
    mk("iat_not_future", L.k, parent ? "k" : "f", () => t.iat <= now + lim.maxIatSkew, "iat is more than MAX_IAT_SKEW in the future"),
    mk("exp_after_iat", L.l, parent ? "l" : "g", () => t.exp > t.iat, "exp is not after iat"),
    mk("lifetime", L.l, parent ? "l" : "h", () => t.exp <= t.iat + lim.maxTokenLifetime, "lifetime exceeds MAX_TOKEN_LIFETIME"),
  ];
}

/** Steps 3m / 4n: the count of attenuating_agent_token entries. */
function entryCount(n: N, root: boolean): Check {
  return {
    name: "aat_entry_count", step: root ? 3 : 4, seq: root ? 13 : n.index * 100 + L.n, token: n.index,
    run() {
      const c = n.claims.entryCount;
      if (root) return c === 1 ? undefined : deny("malformed", "AAT-01 §3.3, §7 step 3m", `root needs exactly one ${AAT_TYPE} entry, found ${c}`);
      return c <= 1 ? undefined : deny("malformed", "AAT-01 §3.3, §7 step 4n", `at most one ${AAT_TYPE} entry is allowed, found ${c}`);
    },
  };
}

function constraintDepthCheck(n: N, root: boolean, ctx: ChainContext<T>): Check {
  return {
    name: "constraint_depth", step: root ? 3 : 4, seq: root ? 14 : n.index * 100 + L.o, token: n.index,
    run() {
      const max = limits(ctx.options).maxConstraintDepth;
      for (const args of n.claims.tools.values()) {
        for (const c of args.values()) {
          if (constraintDepth(c) > max) return deny("constraint_depth", `AAT-01 §3.4, §7 step ${root ? "3n" : "4o"}`, `constraint tree deeper than MAX_CONSTRAINT_DEPTH ${max}`);
        }
      }
      return undefined;
    },
  };
}

/** Step 4p: I4 capability monotonicity (§4.5), p1, p2, p4. */
function capabilityChecks(parent: N, child: N): Check[] {
  const seq = child.index * 100 + L.p;
  const sec = (p: string) => `AAT-01 §4.5, §7 step 4${p}`;
  const mk = (name: string, p: string, run: () => string | undefined): Check => ({
    name, step: 4, seq, token: child.index, run: () => { const m = run(); return m ? deny("I4", sec(p), m) : undefined; },
  });
  return [
    mk("tools_subset", "p1", () => {
      for (const tool of child.claims.tools.keys()) if (!parent.claims.tools.has(tool)) return `tool ${JSON.stringify(tool)} is not authorized by the parent`;
      return undefined;
    }),
    mk("argument_keys_preserved", "p2", () => {
      for (const [tool, cArgs] of child.claims.tools) {
        const pArgs = parent.claims.tools.get(tool);
        if (!pArgs || pArgs.size === 0) continue; // p3: an open-world parent lets the child introduce keys
        for (const k of cArgs.keys()) if (!pArgs.has(k)) return `${tool}: argument ${JSON.stringify(k)} added to a constrained tool`;
        for (const k of pArgs.keys()) if (!cArgs.has(k)) return `${tool}: argument ${JSON.stringify(k)} dropped from a constrained tool`;
      }
      return undefined;
    }),
    mk("constraint_subsumption", "p4", () => {
      for (const [tool, cArgs] of child.claims.tools) {
        const pArgs = parent.claims.tools.get(tool);
        if (!pArgs) continue;
        for (const [k, c] of cArgs) {
          const pc = pArgs.get(k);
          if (pc && !subsumes(c, pc)) return `${tool}.${k}: ${c.type} does not subsume parent ${pc.type}`;
        }
      }
      return undefined;
    }),
  ];
}

export const aat01: Profile<T> = {
  name: "aat-01",
  parse,
  declaredParentHash: (c) => c.parHash,
  preflight,
  sharedChecks,
  tokenChecks(n, ctx) {
    const out: Check[] = [];
    if (n.index === 0) {
      // Step 2c: jti values unique over the presented chain (token-instance cycle detection).
      out.push({
        name: "jti_unique", step: 2, seq: 3, token: 0,
        run() {
          const seen = new Set<string>();
          for (const t of ctx.tokens) {
            if (seen.has(t.claims.jti)) return deny("jti_cycle", "AAT-01 §7 step 2c", `jti ${JSON.stringify(t.claims.jti)} appears more than once`);
            seen.add(t.claims.jti);
          }
          return undefined;
        },
      });
    }
    out.push({
      name: "no_sub", step: 0, seq: 0, token: n.index,
      run: () => limits(ctx.options).rejectSub && n.claims.claims.sub !== undefined ? deny("malformed", "AAT-01 §3.2", "sub is intentionally omitted from AATs") : undefined,
    });
    out.push({
      name: "del_max_depth_bound", step: n.index === 0 ? 3 : 4, seq: n.index === 0 ? 12 : n.index * 100 + L.g, token: n.index,
      run: () => n.claims.delMaxDepth <= limits(ctx.options).maxDelegationDepth ? undefined : deny("I2", "AAT-01 §4.3, §7 step 3i", "del_max_depth exceeds MAX_DELEGATION_DEPTH"),
    });
    return out;
  },
  rootChecks(root, ctx) {
    return [
      { name: "root_del_depth_zero", step: 3, seq: 3, token: 0, run: () => root.claims.delDepth === 0 ? undefined : deny("root_invalid", "AAT-01 §7 step 3c", "root del_depth must be 0") },
      { name: "root_par_hash_absent", step: 3, seq: 4, token: 0, run: () => root.claims.parHash === undefined ? undefined : deny("root_invalid", "AAT-01 §3.2, §7 step 3d", "par_hash MUST be absent in the root") },
      ...timeChecks(root, undefined, ctx),
      { name: "root_iss_uri", step: 3, seq: 11, token: 0, run: () => /^[A-Za-z][A-Za-z0-9+.-]*:\S+$/.test(root.claims.iss) ? undefined : deny("root_invalid", "AAT-01 §3.2, §7 step 3k", "root iss must be a URI") },
      entryCount(root, true),
      constraintDepthCheck(root, true, ctx),
    ];
  },
  linkChecks(parent, child, ctx) {
    const b = child.index * 100;
    const c = child.claims;
    const p = parent.claims;
    const i2 = (name: string, letter: string, seq: number, ok: boolean, message: string): Check => ({
      name, step: 4, seq: b + seq, token: child.index, run: () => ok ? undefined : deny("I2", `AAT-01 §4.3, §7 step 4${letter}`, message),
    });
    return [
      { name: "delegation_authority", step: 4, seq: b + L.c, token: child.index, run: () => equal(c.iss, thumbprintUri(p.jwk)) ? undefined : deny("I1", "AAT-01 §4.2, §7 step 4c", "iss is not the JWK Thumbprint URI of the parent's cnf.jwk") },
      i2("depth_increment", "d", L.d, c.delDepth === p.delDepth + 1, "del_depth is not the parent's plus one"),
      i2("depth_within_parent_max", "e", L.e, c.delDepth <= p.delMaxDepth, "del_depth exceeds the parent's del_max_depth"),
      i2("depth_within_limit", "f", L.f, c.delDepth <= limits(ctx.options).maxDelegationDepth, "del_depth exceeds MAX_DELEGATION_DEPTH"),
      i2("max_depth_not_raised", "g", L.g, c.delMaxDepth <= p.delMaxDepth, "del_max_depth exceeds the parent's"),
      ...timeChecks(child, parent, ctx),
      i2("depth_within_own_max", "m", L.m, c.delDepth <= c.delMaxDepth, "del_depth exceeds the token's own del_max_depth"),
      entryCount(child, false),
      constraintDepthCheck(child, false, ctx),
      ...capabilityChecks(parent, child),
    ];
  },
  leafChecks(leaf, ctx) {
    const out: Check[] = [
      {
        name: "chain_length", step: 5, seq: 0, token: leaf.index,
        run: () => ctx.tokens.length === leaf.claims.delDepth + 1 ? undefined : deny("chain_length", "AAT-01 §7 step 5", `chain has ${ctx.tokens.length} tokens, leaf del_depth is ${leaf.claims.delDepth}`),
      },
      {
        name: "leaf_entry", step: 6, seq: 0, token: leaf.index,
        run: () => leaf.claims.entryCount === 1 ? undefined : deny("authorization_denied", "AAT-01 §3.3, §7 step 6a", `leaf needs exactly one ${AAT_TYPE} entry, found ${leaf.claims.entryCount}`),
      },
    ];
    const req = ctx.options.request?.aat;
    if (req) {
      out.push({
        name: "leaf_arguments", step: 6, seq: 1, token: leaf.index,
        run() {
          const why = authorizeInvocation(leaf.claims.tools, req.tool, req.args);
          return why ? deny("authorization_denied", "AAT-01 §3.3, §7 step 6b", why) : undefined;
        },
      });
      out.push(...popChecks(leaf, req, ctx.options));
    }
    return out;
  },
};
