import { createPublicKey, timingSafeEqual, type KeyObject } from "node:crypto";
import type { Node, VerifyOptions, WalkSuccess } from "../chain.js";
import { b64urlDecodeStrict } from "../encoding.js";
import { parentHash } from "../hash.js";
import { okpThumbprint } from "../holder.js";
import { ExactNumber, isExactObject, parseJsonExact, type ExactObject, type ExactValue, type JsonObject, type JsonValue } from "../json.js";
import { verifyJws, type ParsedJws } from "../jws.js";
import { fail, type Failure, type Outcome } from "../result.js";
import { AAT_DEFAULTS, AAT_TYPE, THUMBPRINT_PREFIX, type AatOptions } from "./aat01.js";
import { authorizeArgs, constraintsNarrow, keyRules, parseArgMap, requiredKept, type ArgMap, type ToolMap } from "./aat02-constraints.js";
import { popStep, readInvocation, type PopInput } from "./aat02-pop.js";

/**
 * draft-niyikiza-oauth-attenuating-agent-tokens-02. "§n" are sections of that
 * draft; "step 4p2" is a step of its §8 algorithm, and every failure carries
 * the step that denied in `Failure.step`.
 *
 * Unlike aat-01, this profile does not go through `walkChain`: -02 §8 asks
 * that each token's claims be parsed only after its signature verifies (3b,
 * 4b, 7b), so the steps run here one by one, in the order §8 lists them,
 * pair by pair for step 4. Only step 2c reads a payload before its signature
 * (the `jti`, untrusted).
 */

/** -02 §8 inputs: trust anchors are (issuer, public key) pairs. */
export interface TrustAnchor {
  iss: string;
  jwk: Readonly<Record<string, unknown>>;
}

/** -02 §7.4: a presentation carried as JSON. Unrecognized members are ignored. */
export interface Aat02Presentation {
  aat_chain: readonly string[];
  aat_pop: string;
}

export interface Aat02Token {
  claims: ExactObject;
  jti: string;
  iss: string;
  iat: number;
  exp: number;
  delDepth: number;
  delMaxDepth: number;
  parHash?: string;
  jwk: JsonObject;
  key: KeyObject;
  /** The `tools` map of the single attenuating_agent_token entry. */
  tools: ToolMap;
}

type Limits = Required<Omit<AatOptions, "popAudience" | "popNonces" | "popJtiCache" | "maxStackSize">> &
  Pick<AatOptions, "popAudience" | "popNonces" | "popJtiCache">;

/** -02 defaults: the draft's recommendations, and MAX_DELEGATION_DEPTH at its floor of 8 (§4.3). */
export const AAT02_DEFAULTS = {
  ...AAT_DEFAULTS,
  maxDelegationDepth: 8,
  maxChainSize: 262144,
  requireChainAudience: false,
  requirePopAudience: false,
  // -02 §3.2 keeps "intentionally omits the sub claim" and §3.4 says unrecognized claims MUST be ignored.
  rejectSub: false,
} as const;

export function limits02(opts: VerifyOptions): Limits {
  const lim = { ...AAT02_DEFAULTS, ...opts.aat } as Limits;
  // §4.3: "MAX_DELEGATION_DEPTH MUST be at least 8". A smaller value is a configuration error, not a verdict.
  if (lim.maxDelegationDepth < 8) throw new Error("aat-02: maxDelegationDepth must be at least 8 (-02 §4.3)");
  return lim;
}

/** JSON nesting allowed in a payload: deep enough for any constraint tree MAX_CONSTRAINT_DEPTH permits. */
const maxJsonDepth = (lim: Limits): number => Math.max(64, 2 * lim.maxConstraintDepth + 32);

const SEC = "AAT-02 §8";
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
/** Header parameters this enforcement point understands for `crit` (RFC 7515 §4.1.11). None. */
const UNDERSTOOD_CRIT: readonly string[] = [];

export function deny(step: string, code: string, message: string, token?: number): Failure {
  return fail(code, `${SEC} step ${step}`, message, { step, check: `step_${step}`, ...(token !== undefined && { token }) });
}

export function equalCt(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

/** A JSON number with no fraction or exponent part (§3.2), as a double. */
export function integer(v: ExactValue | undefined): number | undefined {
  return v instanceof ExactNumber && v.integerSyntax ? v.value : undefined;
}

const nonNegInt = (v: ExactValue | undefined): number | undefined => {
  const n = integer(v);
  return n !== undefined && n >= 0 ? n : undefined;
};

const nonEmptyString = (v: ExactValue | undefined): v is string => typeof v === "string" && v !== "";

/** The three segments of a compact JWS, decoded. `undefined` if it is not one. */
export interface Segments {
  compact: string;
  h: string;
  p: string;
  headerBytes: Uint8Array;
  payloadBytes: Uint8Array;
  signature?: Uint8Array;
}

export function split(compact: string): Segments | undefined {
  const parts = compact.split(".");
  if (parts.length !== 3) return undefined;
  const [h, p, s] = parts as [string, string, string];
  const headerBytes = b64urlDecodeStrict(h);
  const payloadBytes = b64urlDecodeStrict(p);
  if (!headerBytes || !payloadBytes || h === "" || p === "") return undefined;
  const signature = b64urlDecodeStrict(s);
  return { compact, h, p, headerBytes, payloadBytes, ...(signature && { signature }) };
}

export function toParsed(seg: Segments, header: ExactObject): ParsedJws {
  return {
    compact: seg.compact,
    headerBytes: seg.headerBytes,
    payloadBytes: seg.payloadBytes,
    signature: seg.signature ?? new Uint8Array(),
    header: header as unknown as JsonObject,
    alg: "Ed25519",
    signingInput: new Uint8Array(Buffer.from(`${seg.h}.${seg.p}`, "ascii")),
  };
}

/**
 * Steps 3a / 4a / 7a: allowlist, consistency with an OKP Ed25519 verifying
 * key (the only kind this verifier holds), explicit `typ`, and `crit`.
 */
export function headerCheck(seg: Segments, typ: string, opts: VerifyOptions): Outcome<ExactObject> {
  const parsed = parseJsonExact(seg.headerBytes, "RFC 7515 §4");
  if (!parsed.ok || !isExactObject(parsed.value)) return fail("malformed", "RFC 7515 §4", "protected header is not a JSON object");
  const h = parsed.value;
  if (typeof h.alg !== "string") return fail("signature_invalid", "§3.5", "alg is absent");
  if (h.alg === "none") return fail("signature_invalid", "§9.11", 'alg "none" is never acceptable');
  // §9.11: "the deprecated polymorphic EdDSA MUST NOT be used or accepted"; Ed25519 is the only algorithm implemented.
  const allow: readonly string[] = (opts.acceptedAlgs ?? ["Ed25519"]).filter((a) => a === "Ed25519");
  if (!allow.includes(h.alg)) return fail("signature_invalid", "§3.5, §9.11", `alg ${JSON.stringify(h.alg)} is not on the allowlist`);
  if (h.typ !== typ) return fail("typ", "§3.5", `typ must be ${JSON.stringify(typ)}, found ${JSON.stringify(h.typ ?? null)}`);
  if (Object.hasOwn(h, "crit")) {
    const crit = h.crit;
    if (!Array.isArray(crit) || crit.length === 0 || !crit.every((x) => typeof x === "string")) {
      return fail("crit", "§3.5, RFC 7515 §4.1.11", "crit must be a non-empty array of strings");
    }
    const unknown = crit.find((x) => !UNDERSTOOD_CRIT.includes(x as string));
    if (unknown !== undefined) return fail("crit", "§3.5, RFC 7515 §4.1.11", `crit lists ${JSON.stringify(unknown)}, which this enforcement point does not understand`);
  }
  // §3.5: jwk, jku, x5c, x5u are never key sources and kid is not used (one key per anchor); other parameters are ignored.
  return { ok: true, value: h };
}

/**
 * Steps 3l / 4b2: `cnf.jwk` encodes a public key. This verifier holds only
 * OKP Ed25519 keys, so any other key is one it cannot use (the -02 suite
 * expects the denial here, not at 4a/7a).
 */
export function holderKey(claims: ExactObject): { jwk: JsonObject; key: KeyObject } | string {
  const cnf = claims.cnf;
  if (!isExactObject(cnf) || !isExactObject(cnf.jwk)) return "cnf must be an object containing jwk";
  return publicEd25519(cnf.jwk);
}

export function publicEd25519(jwk: Readonly<Record<string, unknown>>): { jwk: JsonObject; key: KeyObject } | string {
  const priv = PRIVATE_JWK_MEMBERS.find((m) => Object.hasOwn(jwk, m));
  if (priv) return `jwk carries the private key parameter ${priv}`;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") return "jwk is not an OKP Ed25519 key";
  const x = typeof jwk.x === "string" ? b64urlDecodeStrict(jwk.x) : undefined;
  if (!x || x.length !== 32) return "jwk x is not a 32-byte base64url value";
  try {
    return { jwk: jwk as JsonObject, key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x as string }, format: "jwk" }) };
  } catch {
    return "jwk is not a valid Ed25519 public key";
  }
}

export function thumbprintUri02(jwk: JsonObject): string {
  return THUMBPRINT_PREFIX + okpThumbprint(jwk);
}

/** Steps 3m / 4n: exactly one attenuating_agent_token entry whose tools is an object of objects. Returns the raw tools. */
function aatEntry(details: ExactValue | undefined): ExactObject | string {
  if (!Array.isArray(details)) return "authorization_details is not an array";
  const entries = details.filter((e) => isExactObject(e) && e.type === AAT_TYPE) as ExactObject[];
  if (entries.length !== 1) return `exactly one ${AAT_TYPE} entry is required, found ${entries.length}`;
  const tools = (entries[0] as ExactObject).tools;
  if (!isExactObject(tools)) return "the entry's tools member is absent or not an object";
  for (const [tool, m] of Object.entries(tools)) if (!isExactObject(m)) return `tools[${JSON.stringify(tool)}] is not an object`;
  return tools;
}

/** Steps 3n / 4o over every constraint map of the entry. */
function toolMap(tools: ExactObject, lim: Limits): ToolMap | { code: string; message: string } {
  const out = new Map<string, ArgMap>();
  for (const [tool, raw] of Object.entries(tools)) {
    const m = parseArgMap(raw, lim.maxConstraintDepth);
    if ("kind" in m) return { code: m.kind, message: `${tool}: ${m.message}` };
    out.set(tool, m);
  }
  return out;
}

/** Steps 3b / 4b / 7b after signature verification: strict parse, duplicate members rejected anywhere. */
function claimsOf(seg: Segments, lim: Limits): ExactObject | string {
  const parsed = parseJsonExact(seg.payloadBytes, "§8", { maxDepth: maxJsonDepth(lim) });
  if (!parsed.ok) return parsed.message;
  if (!isExactObject(parsed.value)) return "payload is not a JSON object";
  return parsed.value;
}

type N = Node<Aat02Token>;

/**
 * -02 §8. `input` is the chain (root first) or a §7.4 presentation. Without
 * `opts.request.aat02` the chain is verified alone: steps 1-5 and 6a, 6c.
 */
export function verifyAat02(input: readonly string[] | Aat02Presentation, opts: VerifyOptions): WalkSuccess<Aat02Token> | Failure {
  const lim = limits02(opts);
  const presentation = Array.isArray(input) ? undefined : (input as Aat02Presentation);
  const tokens: readonly string[] = presentation ? presentation.aat_chain : (input as readonly string[]);
  if (!Array.isArray(tokens) || !tokens.every((t) => typeof t === "string")) return deny("1", "malformed", "aat_chain must be an array of strings");
  const steps = new Set<number>();

  // Step 1.
  steps.add(1);
  if (tokens.length === 0) return deny("1", "chain_empty", "the chain is empty");

  // Step 2: sizes, then the untrusted jti of every token (cycle detection).
  steps.add(2);
  let total = 0;
  for (const [i, t] of tokens.entries()) {
    const size = Buffer.byteLength(t, "utf8");
    total += size;
    if (size > lim.maxTokenSize) return deny("2a", "size_limit", `token exceeds MAX_TOKEN_SIZE ${lim.maxTokenSize}`, i);
  }
  if (total > lim.maxChainSize) return deny("2b", "size_limit", `chain exceeds MAX_CHAIN_SIZE ${lim.maxChainSize}`);
  const segs: Segments[] = [];
  const seen = new Set<string>();
  for (const [i, t] of tokens.entries()) {
    const seg = split(t);
    if (!seg) return deny("2c", "malformed", "not a compact JWS; no jti can be extracted", i);
    // Minimal extraction: duplicates tolerated here (first kept); step 3b/4b rejects them once the signature verifies.
    const pre = parseJsonExact(seg.payloadBytes, "§8 step 2c", { duplicates: "first", maxDepth: maxJsonDepth(lim) });
    const jti = pre.ok && isExactObject(pre.value) ? pre.value.jti : undefined;
    if (typeof jti !== "string") return deny("2c", "malformed", "no string-valued jti can be extracted", i);
    if (seen.has(jti)) return deny("2c", "jti_cycle", `jti ${JSON.stringify(jti)} appears more than once`, i);
    seen.add(jti);
    segs.push(seg);
  }

  // Step 3: the root.
  steps.add(3);
  const rootSeg = segs[0] as Segments;
  const rh = headerCheck(rootSeg, "aat+jwt", opts);
  if (!rh.ok) return deny("3a", rh.code, rh.message, 0);
  const rootJws = toParsed(rootSeg, rh.value);
  const anchors = (opts.anchors ?? []).flatMap((a) => {
    const k = publicEd25519(a.jwk);
    return typeof k === "string" ? [] : [{ iss: a.iss, key: k.key }];
  });
  const verifying = rootSeg.signature ? anchors.filter((a) => verifyJws(rootJws, { alg: "Ed25519", publicKey: a.key })) : [];
  if (verifying.length === 0) return deny("3b", "signature_invalid", "root signature does not verify under any trust anchor", 0);
  const rc = claimsOf(rootSeg, lim);
  if (typeof rc === "string") return deny("3b", "malformed", rc, 0);
  const rIat = integer(rc.iat);
  const rExp = integer(rc.exp);
  if (rIat === undefined || rExp === undefined) return deny("3b", "malformed", "iat and exp must be NumericDates with no fraction or exponent (§3.2)", 0);
  if (lim.rejectSub && Object.hasOwn(rc, "sub")) return deny("3b", "malformed", "sub present and this enforcement point rejects it (local policy)", 0);
  if (integer(rc.del_depth) !== 0) return deny("3c", "root_invalid", "root del_depth must be the integer 0", 0);
  if (Object.hasOwn(rc, "par_hash")) return deny("3d", "root_invalid", "par_hash MUST be absent in the root", 0);
  const { now } = opts;
  if (!(rExp > now)) return deny("3e", "I3", "root has expired", 0);
  if (!(rIat <= now + lim.maxIatSkew)) return deny("3f", "I3", "root iat is more than MAX_IAT_SKEW in the future", 0);
  if (!(rExp > rIat)) return deny("3g", "I3", "root exp is not after its iat", 0);
  if (!(rExp <= rIat + lim.maxTokenLifetime)) return deny("3h", "I3", "root lifetime exceeds MAX_TOKEN_LIFETIME", 0);
  const rMax = nonNegInt(rc.del_max_depth);
  if (rMax === undefined) return deny("3i", "malformed", "del_max_depth must be a non-negative integer", 0);
  if (rMax > lim.maxDelegationDepth) return deny("3i", "I2", "del_max_depth exceeds MAX_DELEGATION_DEPTH", 0);
  if (!nonEmptyString(rc.jti)) return deny("3j", "malformed", "jti must be a non-empty string", 0);
  if (typeof rc.iss !== "string" || !/^[A-Za-z][A-Za-z0-9+.-]*:\S+$/.test(rc.iss)) return deny("3k", "root_invalid", "root iss must be a URI", 0);
  // §8 step 3k, RFC 8725 §3.8: iss is the issuer of the anchor whose key verified the signature.
  if (!verifying.some((a) => a.iss === rc.iss)) return deny("3k", "root_invalid", "root iss is not the issuer of the trust anchor that verified it", 0);
  const rKey = holderKey(rc);
  if (typeof rKey === "string") return deny("3l", "malformed", rKey, 0);
  if (!Array.isArray(rc.authorization_details) || rc.authorization_details.length === 0) {
    return deny("3m", "malformed", "authorization_details must be a non-empty array", 0);
  }
  const rTools = aatEntry(rc.authorization_details);
  if (typeof rTools === "string") return deny("3m", "malformed", rTools, 0);
  const rMap = toolMap(rTools, lim);
  if ("code" in rMap) return deny("3n", rMap.code, rMap.message, 0);
  const chain: N[] = [
    {
      index: 0,
      jws: rootJws,
      claims: { claims: rc, jti: rc.jti, iss: rc.iss, iat: rIat, exp: rExp, delDepth: 0, delMaxDepth: rMax, jwk: rKey.jwk, key: rKey.key, tools: rMap as ToolMap },
    },
  ];

  // Step 4: each adjacent pair, all of pair k before pair k+1.
  for (let i = 1; i < segs.length; i++) {
    steps.add(4);
    const parent = (chain[i - 1] as N).claims;
    const seg = segs[i] as Segments;
    const h = headerCheck(seg, "aat+jwt", opts);
    if (!h.ok) return deny("4a", h.code, h.message, i);
    const jws = toParsed(seg, h.value);
    if (!seg.signature || !verifyJws(jws, { alg: "Ed25519", publicKey: parent.key })) {
      return deny("4b", "signature_invalid", "signature does not verify under the parent's cnf.jwk (I1)", i);
    }
    const c = claimsOf(seg, lim);
    if (typeof c === "string") return deny("4b", "malformed", c, i);
    if (lim.rejectSub && Object.hasOwn(c, "sub")) return deny("4b", "malformed", "sub present and this enforcement point rejects it (local policy)", i);
    if (!nonEmptyString(c.jti)) return deny("4b1", "malformed", "jti must be a non-empty string", i);
    const key = holderKey(c);
    if (typeof key === "string") return deny("4b2", "malformed", key, i);
    if (!Array.isArray(c.authorization_details)) return deny("4b3", "malformed", "authorization_details must be an array", i);
    const dd = nonNegInt(c.del_depth);
    const dm = nonNegInt(c.del_max_depth);
    if (dd === undefined || dm === undefined) return deny("4b4", "malformed", "del_depth and del_max_depth must be non-negative integers", i);
    const iat = integer(c.iat);
    const exp = integer(c.exp);
    if (typeof c.iss !== "string" || typeof c.par_hash !== "string" || iat === undefined || exp === undefined) {
      return deny("4b5", "malformed", "iss and par_hash must be strings, iat and exp NumericDates", i);
    }
    if (!equalCt(c.iss, thumbprintUri02(parent.jwk))) return deny("4c", "I1", "iss is not the JWK Thumbprint URI of the parent's cnf.jwk", i);
    if (dd !== parent.delDepth + 1) return deny("4d", "I2", "del_depth is not the parent's plus one", i);
    if (dd > parent.delMaxDepth) return deny("4e", "I2", "del_depth exceeds the parent's del_max_depth", i);
    if (dd > lim.maxDelegationDepth) return deny("4f", "I2", "del_depth exceeds MAX_DELEGATION_DEPTH", i);
    if (dm > parent.delMaxDepth) return deny("4g", "I2", "del_max_depth exceeds the parent's", i);
    if (!(exp <= parent.exp)) return deny("4h", "I3", "exp exceeds the parent's exp", i);
    if (!(exp > now)) return deny("4i", "I3", "token has expired", i);
    if (!(iat >= parent.iat)) return deny("4j", "I3", "iat precedes the parent's iat", i);
    if (!(iat <= now + lim.maxIatSkew)) return deny("4k", "I3", "iat is more than MAX_IAT_SKEW in the future", i);
    if (!(exp > iat)) return deny("4l", "I3", "exp is not after iat", i);
    if (!(dd <= dm)) return deny("4m", "I2", "del_depth exceeds the token's own del_max_depth", i);
    const tools = aatEntry(c.authorization_details);
    if (typeof tools === "string") return deny("4n", "malformed", tools, i);
    const map = toolMap(tools, lim);
    if ("code" in map) return deny("4o", map.code, map.message, i);
    for (const tool of map.keys()) {
      if (!parent.tools.has(tool)) return deny("4p1", "I4", `tool ${JSON.stringify(tool)} is not authorized by the parent`, i);
    }
    for (const [rule, step] of [[keyRules, "4p2"], [requiredKept, "4p3"], [constraintsNarrow, "4p4"]] as const) {
      for (const [tool, cm] of map) {
        const why = rule(parent.tools.get(tool) as ArgMap, cm);
        if (why) return deny(step, "I4", `${tool}: ${why}`, i);
      }
    }
    if (!equalCt(c.par_hash, parentHash(chain[i - 1]!.jws.compact))) {
      return deny("4q", "I5", "par_hash does not equal SHA-256 of the parent signing input", i);
    }
    chain.push({
      index: i,
      jws,
      claims: { claims: c, jti: c.jti, iss: c.iss, iat, exp, delDepth: dd, delMaxDepth: dm, parHash: c.par_hash, jwk: key.jwk, key: key.key, tools: map },
    });
  }

  // Step 5 (defense in depth).
  steps.add(5);
  const leaf = chain[chain.length - 1] as N;
  if (chain.length !== leaf.claims.delDepth + 1) return deny("5", "chain_length", `chain has ${chain.length} tokens, leaf del_depth is ${leaf.claims.delDepth}`, leaf.index);

  // Step 6. 6a holds by 3m/4n (every token carries exactly one entry).
  steps.add(6);
  const ep = opts.audience ?? lim.popAudience;
  const req = opts.request?.aat02;
  let args: Readonly<Record<string, JsonValue>> | undefined;
  if (req) {
    const tool = leaf.claims.tools.get(req.tool);
    const inv = readInvocation(req.args);
    if (typeof inv === "string") return deny("6b", "authorization_denied", inv, leaf.index);
    if (!tool) return deny("6b", "authorization_denied", `tool ${JSON.stringify(req.tool)} is not in the leaf's attenuating_agent_token entry`, leaf.index);
    const why = authorizeArgs(tool, inv);
    if (why) return deny("6b", "authorization_denied", why, leaf.index);
    args = inv;
  }
  let anyAud = false;
  for (const n of chain) {
    if (!Object.hasOwn(n.claims.claims, "aud")) continue;
    anyAud = true;
    const aud = n.claims.claims.aud;
    const values = typeof aud === "string" ? [aud] : Array.isArray(aud) && aud.every((v) => typeof v === "string") ? (aud as string[]) : undefined;
    if (!values) return deny("6c", "audience", "aud must be a string or an array of strings", n.index);
    if (ep === undefined || !values.some((v) => v === ep)) return deny("6c", "audience", "aud does not identify this enforcement point", n.index);
  }
  if (lim.requireChainAudience && !anyAud) return deny("6c", "audience", "chain audience restriction is required and no token carries aud", leaf.index);

  // Step 7.
  if (req && args) {
    steps.add(7);
    const pop = req.pop ?? presentation?.aat_pop;
    if (typeof pop !== "string") return deny("7a", "I6", "no PoP JWT presented", leaf.index);
    const input: PopInput = { pop, tool: req.tool, args, leaf, ...(ep !== undefined && { audience: ep }) };
    const f = popStep(input, opts, lim, maxJsonDepth(lim));
    if (f) return f;
  }
  return { ok: true, chain, stepsPerformed: [...steps].sort((a, b) => a - b) };
}

export type { Limits as Aat02Limits };
