import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChain } from "../index.js";
import type { AatOptions } from "../profiles/aat01.js";
import type { Aat02Presentation, TrustAnchor } from "../profiles/aat02.js";

/**
 * Runs the AAT JWS vector suite for draft-niyikiza-oauth-attenuating-agent-tokens-02
 * (vectors/aat02/aat-jws-vectors.json) through `verifyChain(…, "aat-02", …)`
 * and writes results/aat02-results.json in the format compare_results.py reads:
 * `{"J.1": "PERMIT", "J.2": {"verdict": "DENY", "step": "2c"}}`.
 *
 *   npm run suite:aat02 [-- <suite.json> [<results.json>]]
 */

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const SUITE_PATH = resolve(ROOT, "vectors/aat02/aat-jws-vectors.json");
export const RESULTS_PATH = resolve(ROOT, "results/aat02-results.json");

interface Params {
  now?: number;
  max_iat_skew?: number;
  max_token_lifetime?: number;
  max_delegation_depth?: number;
  max_constraint_depth?: number;
  max_token_size?: number;
  max_chain_size?: number;
  pop_window?: number;
  audience?: string;
}

interface Vector {
  id: string;
  title: string;
  now: number;
  tool: string;
  args_json: string;
  policy: { require_chain_aud?: boolean; require_pop_aud?: boolean; nonce?: string; track_pop_jti?: boolean };
  params: Params;
  replay_state: { before: string[]; after: string[] } | null;
  chain_compact: string[];
  pop: { compact: string };
  presentation: Aat02Presentation;
  expected: { verdict: "PERMIT" | "DENY"; step?: string | null };
}

export interface Suite {
  spec: string;
  params: Params;
  trust_anchors: TrustAnchor[];
  vectors: Vector[];
}

export type Verdict = "PERMIT" | { verdict: "DENY"; step?: string; reason: string } | { verdict: "SKIP"; reason: string };

export interface VectorRun {
  id: string;
  result: Verdict;
  /** Replay cache after the run, for vectors that track PoP jti (step 7i). */
  replayAfter?: string[];
}

/** Vectors that need something this verifier does not implement: id -> reason. Empty: every vector runs. */
export const SKIPS: Readonly<Record<string, string>> = {};

/** Map the suite's params and a vector's policy onto `AatOptions` (-02 §4.3, §4.3.1, §4.4, §3.4, §9.9, §8 steps 6c-7i). */
export function optionsFor(suite: Suite, v: Vector): { aat: AatOptions; audience?: string; now: number } {
  const p: Params = { ...suite.params, ...v.params };
  const aat: AatOptions = {
    ...(p.max_iat_skew !== undefined && { maxIatSkew: p.max_iat_skew }),
    ...(p.max_token_lifetime !== undefined && { maxTokenLifetime: p.max_token_lifetime }),
    ...(p.max_delegation_depth !== undefined && { maxDelegationDepth: p.max_delegation_depth }),
    ...(p.max_constraint_depth !== undefined && { maxConstraintDepth: p.max_constraint_depth }),
    ...(p.max_token_size !== undefined && { maxTokenSize: p.max_token_size }),
    ...(p.max_chain_size !== undefined && { maxChainSize: p.max_chain_size }),
    ...(p.pop_window !== undefined && { popSkew: p.pop_window }),
    ...(v.policy.require_chain_aud && { requireChainAudience: true }),
    ...(v.policy.require_pop_aud && { requirePopAudience: true }),
    ...(v.policy.nonce !== undefined && { popNonces: [v.policy.nonce] }),
    ...(v.policy.track_pop_jti && { popJtiCache: new Set(v.replay_state?.before ?? []) }),
  };
  return { aat, ...(p.audience !== undefined && { audience: p.audience }), now: v.now ?? p.now };
}

/** Run one vector. `form` selects the input: the §7.4 presentation object or the bare chain plus PoP. */
export function runVector(suite: Suite, v: Vector, form: "presentation" | "arrays" = "presentation"): VectorRun {
  const skip = SKIPS[v.id];
  if (skip) return { id: v.id, result: { verdict: "SKIP", reason: skip } };
  const { aat, audience, now } = optionsFor(suite, v);
  const r = verifyChain(form === "presentation" ? v.presentation : v.chain_compact, "aat-02", {
    anchors: suite.trust_anchors,
    aat,
    now,
    ...(audience !== undefined && { audience }),
    request: { aat02: { tool: v.tool, args: v.args_json, ...(form === "arrays" && { pop: v.pop.compact }) } },
  });
  const result: Verdict = r.ok ? "PERMIT" : { verdict: "DENY", ...(r.step !== undefined && { step: r.step }), reason: r.message };
  return { id: v.id, result, ...(aat.popJtiCache && { replayAfter: [...aat.popJtiCache] }) };
}

export function loadSuite(path = SUITE_PATH): Suite {
  return JSON.parse(readFileSync(path, "utf8")) as Suite;
}

export function runSuite(suite: Suite, form: "presentation" | "arrays" = "presentation"): VectorRun[] {
  return suite.vectors.map((v) => runVector(suite, v, form));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const suitePath = process.argv[2] ? resolve(process.argv[2]) : SUITE_PATH;
  const out = process.argv[3] ? resolve(process.argv[3]) : RESULTS_PATH;
  const runs = runSuite(loadSuite(suitePath));
  const results: Record<string, Verdict> = {};
  for (const r of runs) results[r.id] = r.result;
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(results, null, 2)}\n`);
  const count = (pred: (v: Verdict) => boolean) => runs.filter((r) => pred(r.result)).length;
  console.log(
    `${runs.length} vectors: ${count((v) => v === "PERMIT")} PERMIT, ${count((v) => typeof v === "object" && v.verdict === "DENY")} DENY, ${count((v) => typeof v === "object" && v.verdict === "SKIP")} SKIP -> ${out}`,
  );
}
