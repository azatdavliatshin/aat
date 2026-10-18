import { verifyJws, parseJws, type ParsedJws, type TrustedKey } from "./jws.js";
import { parentHash } from "./hash.js";
import { fail, type Failure, type Outcome } from "./result.js";
import { timingSafeEqual } from "node:crypto";
import type { AatOptions } from "./profiles/aat01.js";

/**
 * Generic chain walk. A profile supplies claim parsing and its own named
 * checks; the walker owns the two checks every profile shares (step 1:
 * signatures and algorithm list; step 2: parent commitment) and runs all
 * checks in the order of the draft's steps, denying on the first failure.
 *
 * Failure codes use the asor-02 Table 2 vocabulary; other profiles map onto
 * the same names.
 */

export interface Node<T> {
  index: number;
  jws: ParsedJws;
  claims: T;
}

/** Result of one check: undefined = pass, otherwise a failure without position. */
export type CheckResult = { code: string; section: string; message: string } | undefined;

export interface Check {
  /** Stable name of the check, reported in the failure. */
  name: string;
  /** Draft step (0 = parse-time classification, before step 1). */
  step: number;
  /** Order inside one step (e.g. depth before principal in asor-02 step 3). */
  seq: number;
  /** Chain position the check concerns. */
  token?: number;
  run(): CheckResult;
}

export interface VerifyOptions {
  /** Trusted keys by header `kid` (asor-02). */
  keys?: Readonly<Record<string, TrustedKey>>;
  /** Trust anchors, a set of root issuer keys without identifiers (AAT-01 §7 inputs). */
  trustAnchors?: readonly TrustedKey[];
  /** AAT-01 limits and policy; defaults are the draft's recommendations where it gives one. */
  aat?: AatOptions;
  /** Local list of accepted algorithms (asor-02 §6 step 1). Default: EdDSA only. */
  acceptedAlgs?: readonly string[];
  /** Verification time, NumericDate. */
  now: number;
  /** The Enforcement Point's own identifier, for the audience check. Omit to verify the chain alone. */
  audience?: string;
  /** Request-bound inputs (steps 6 and 8). Omit to verify the chain alone. */
  request?: RequestContext;
}

export interface RequestContext {
  dpop?: { proof: string; method: string; url: string };
  action?: { scope: string; params?: Readonly<Record<string, unknown>> };
  /** AAT-01 §7 inputs `tool`, `args`, `pop_jwt` (steps 6 and 7). */
  aat?: { tool: string; args: Readonly<Record<string, unknown>>; pop: string };
  /** Running totals for cumulative constraints, supplied out of band. */
  totals?: Readonly<Record<string, number>>;
}

export interface ChainContext<T> {
  options: VerifyOptions;
  tokens: readonly Node<T>[];
}

export interface Profile<T> {
  name: string;
  /** Parse and classify one token (asor-02 §3, §4, §4.4); failures are `malformed`-class. */
  parse(jws: ParsedJws): Outcome<T>;
  /** The parent commitment a token declares, if any. */
  declaredParentHash(claims: T): string | undefined;
  tokenChecks(node: Node<T>, ctx: ChainContext<T>): Check[];
  rootChecks(root: Node<T>, ctx: ChainContext<T>): Check[];
  linkChecks(parent: Node<T>, child: Node<T>, ctx: ChainContext<T>): Check[];
  leafChecks(leaf: Node<T>, ctx: ChainContext<T>): Check[];
  /** Size and shape limits applied to the raw tokens before any parsing (AAT-01 §7 step 2). */
  preflight?(tokens: readonly string[], opts: VerifyOptions): Failure | undefined;
  /** Replaces the shared signature and parent-commitment checks when the profile selects keys differently. */
  sharedChecks?(chain: readonly Node<T>[], opts: VerifyOptions): Check[];
}

export interface WalkSuccess<T> {
  ok: true;
  chain: readonly Node<T>[];
  /** Draft steps that ran. Steps absent here were not performed (no request, no audience). */
  stepsPerformed: readonly number[];
}

export function defaultSharedChecks<T>(profile: Profile<T>, chain: readonly Node<T>[], opts: VerifyOptions): Check[] {
  const accepted = opts.acceptedAlgs ?? ["EdDSA"];
  const out: Check[] = [];
  for (const node of chain) {
    out.push({
      name: "signature",
      step: 1,
      seq: 0,
      token: node.index,
      run() {
        const section = "asor-02 §6 step 1";
        if (!accepted.includes(node.jws.alg)) {
          return { code: "signature_invalid", section, message: `alg ${node.jws.alg} is not on the accepted list` };
        }
        const kid = node.jws.header.kid;
        const key = typeof kid === "string" ? opts.keys?.[kid] : undefined;
        if (!key) return { code: "signature_invalid", section, message: "no trusted key for this token's kid" };
        if (key.alg !== node.jws.alg) {
          return { code: "signature_invalid", section, message: "alg differs from the one configured for the key" };
        }
        if (!verifyJws(node.jws, key)) return { code: "signature_invalid", section, message: "signature does not verify" };
        return undefined;
      },
    });
  }
  for (const child of chain.slice(1)) {
    const parent = chain[child.index - 1] as Node<T>;
    out.push({
      name: "par_hash",
      step: 2,
      seq: 0,
      token: child.index,
      run() {
        const declared = profile.declaredParentHash(child.claims);
        const expected = parentHash(parent.jws.compact);
        const a = Buffer.from(declared ?? "", "utf8");
        const b = Buffer.from(expected, "utf8");
        const equal = a.length === b.length && timingSafeEqual(a, b); // asor-02 §6 step 2: constant time
        return equal
          ? undefined
          : { code: "par_hash_mismatch", section: "asor-02 §5, §6 step 2", message: "par_hash does not commit to the parent presented" };
      },
    });
  }
  return out;
}

/**
 * Parse every token, then run the profile's and the shared checks in step
 * order. Throws only on programmer error (an empty token list).
 */
export function walkChain<T>(tokens: readonly string[], profile: Profile<T>, opts: VerifyOptions): WalkSuccess<T> | Failure {
  const early = profile.preflight?.(tokens, opts);
  if (early) return early;
  if (tokens.length === 0) throw new Error("walkChain: empty chain");
  const chain: Node<T>[] = [];
  for (const [index, compact] of tokens.entries()) {
    const jws = parseJws(compact);
    if (!jws.ok) {
      // An unusable algorithm is a step 1 denial; structure problems are parse-time.
      const code = jws.code.startsWith("alg_") ? "signature_invalid" : jws.code;
      return { ...jws, code, token: index, check: "jws_parse" };
    }
    const claims = profile.parse(jws.value);
    if (!claims.ok) return { ...claims, token: index, check: claims.check ?? "claims_parse" };
    chain.push({ index, jws: jws.value, claims: claims.value });
  }

  const ctx: ChainContext<T> = { options: opts, tokens: chain };
  const root = chain[0] as Node<T>;
  const leaf = chain[chain.length - 1] as Node<T>;
  const checks: Check[] = [
    ...(profile.sharedChecks?.(chain, opts) ?? defaultSharedChecks(profile, chain, opts)),
    ...chain.flatMap((n) => profile.tokenChecks(n, ctx)),
    ...profile.rootChecks(root, ctx),
    ...chain.slice(1).flatMap((c) => profile.linkChecks(chain[c.index - 1] as Node<T>, c, ctx)),
    ...profile.leafChecks(leaf, ctx),
  ];
  // Array.prototype.sort is stable: equal (step, seq) keep chain order.
  checks.sort((a, b) => a.step - b.step || a.seq - b.seq);
  for (const check of checks) {
    const r = check.run();
    if (r) return fail(r.code, r.section, r.message, { check: check.name, ...(check.token !== undefined && { token: check.token }) });
  }
  return { ok: true, chain, stepsPerformed: [...new Set(checks.map((c) => c.step))].sort((a, b) => a - b) };
}
