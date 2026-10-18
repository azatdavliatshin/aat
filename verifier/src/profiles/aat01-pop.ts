import type { Check, CheckResult, Node, RequestContext, VerifyOptions } from "../chain.js";
import { isObject, jcs, parseJson, type JsonObject, type JsonValue } from "../json.js";
import { parseJws, verifyJws, type ParsedJws } from "../jws.js";
import { satisfies } from "./aat01-constraints.js";
import { limits, type Aat01Token, type ToolMap } from "./aat01.js";

/**
 * AAT-01 §7 steps 6b (closed-world argument check) and 7 (PoP, I6, §5.2,
 * §5.3). Every PoP failure carries code `I6`.
 */

/** Plain JSON data only: no undefined, functions, non-finite numbers, non-plain objects. */
export function toJson(v: unknown): JsonValue | undefined {
  if (v === null || typeof v === "boolean" || typeof v === "string") return v;
  if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
  if (Array.isArray(v)) {
    const out: JsonValue[] = [];
    for (const x of v) {
      const j = toJson(x);
      if (j === undefined) return undefined;
      out.push(j);
    }
    return out;
  }
  if (typeof v === "object") {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) return undefined;
    const out: JsonObject = Object.create(null) as JsonObject;
    for (const [k, x] of Object.entries(v)) {
      const j = toJson(x);
      if (j === undefined) return undefined;
      out[k] = j;
    }
    return out;
  }
  return undefined;
}

/** §7 step 6b. Returns a message when the invocation is denied. */
export function authorizeInvocation(tools: ToolMap, tool: string, args: Readonly<Record<string, unknown>>): string | undefined {
  const constraints = tools.get(tool);
  if (!constraints) return `tool ${JSON.stringify(tool)} is not authorized by the leaf`;
  const values = toJson(args);
  if (values === undefined || !isObject(values)) return "args is not a JSON object";
  if (constraints.size === 0) return undefined; // open world: no argument restriction
  for (const name of Object.keys(values)) {
    if (!constraints.has(name)) return `argument ${JSON.stringify(name)} is not named in the constraint map (closed world)`;
  }
  for (const [name, c] of constraints) {
    if (!Object.hasOwn(values, name)) return `constrained argument ${JSON.stringify(name)} is absent`;
    if (!satisfies(c, values[name] as JsonValue)) return `argument ${JSON.stringify(name)} violates its ${c.type} constraint`;
  }
  return undefined;
}

interface PopState {
  jws?: ParsedJws;
  claims?: JsonObject;
}

const SEC = "AAT-01 §5.3, §7 step 7";
const deny = (section: string, message: string): CheckResult => ({ code: "I6", section, message });

export function popChecks(leaf: Node<Aat01Token>, req: NonNullable<RequestContext["aat"]>, opts: VerifyOptions): Check[] {
  const lim = limits(opts);
  const accepted = opts.acceptedAlgs ?? ["EdDSA"];
  const st: PopState = {};
  const mk = (name: string, seq: number, run: () => CheckResult): Check => ({ name, step: 7, seq, token: leaf.index, run });
  return [
    mk("pop_alg", 1, () => {
      const j = parseJws(req.pop);
      if (!j.ok) return deny(`${SEC}a, §8.13`, `PoP JWT: ${j.message}`);
      // §8.13: the allowlist applies to the PoP JWT independently; leaf.cnf.jwk is OKP Ed25519, which only EdDSA fits.
      if (j.value.alg !== "EdDSA" || !accepted.includes("EdDSA")) return deny(`${SEC}a, §8.13`, `PoP alg ${j.value.alg} is not permitted or does not fit leaf.cnf.jwk`);
      st.jws = j.value;
      return undefined;
    }),
    mk("pop_signature", 2, () => {
      if (!st.jws || !verifyJws(st.jws, { alg: "EdDSA", publicKey: leaf.claims.key })) return deny(`${SEC}b, §4.7`, "PoP signature does not verify under leaf.cnf.jwk");
      return undefined;
    }),
    mk("pop_claims", 3, () => {
      const jws = st.jws as ParsedJws;
      const p = parseJson(jws.payloadBytes, "AAT-01 §5.2");
      if (!p.ok || !isObject(p.value)) return deny("AAT-01 §5.2", "PoP payload is not a JSON object");
      // §5.2: the whole payload MUST be JCS-serialized before signing.
      if (jcs(p.value) !== new TextDecoder().decode(jws.payloadBytes)) return deny("AAT-01 §5.2, RFC 8785", "PoP payload is not the JCS serialization of its claims");
      const c = p.value;
      for (const m of ["jti", "aat_id", "aat_tool"] as const) {
        if (typeof c[m] !== "string") return deny("AAT-01 §5.2", `PoP claim ${m} is required, a string`);
      }
      if (typeof c.iat !== "number") return deny("AAT-01 §5.2", "PoP claim iat is required, a NumericDate");
      if (!isObject(c.hta)) return deny("AAT-01 §5.2", "PoP claim hta is required, an object");
      if (c.aat_aud !== undefined && typeof c.aat_aud !== "string") return deny("AAT-01 §5.2", "PoP claim aat_aud must be a string");
      st.claims = c;
      return undefined;
    }),
    mk("pop_aat_id", 4, () => st.claims?.aat_id === leaf.claims.jti ? undefined : deny(`${SEC}c, §5.3`, "aat_id does not match the leaf jti")),
    mk("pop_audience", 5, () => {
      if (lim.popAudience === undefined) return undefined;
      return st.claims?.aat_aud === lim.popAudience ? undefined : deny(`${SEC}d, §5.3`, "aat_aud is absent or does not identify this enforcement point");
    }),
    mk("pop_tool", 6, () => st.claims?.aat_tool === req.tool ? undefined : deny(`${SEC}e, §3.3.1`, "aat_tool does not equal the invoked tool")),
    mk("pop_args", 7, () => {
      const args = toJson(req.args);
      if (args === undefined || jcs(st.claims?.hta as JsonValue) !== jcs(args)) return deny(`${SEC}f`, "hta does not equal the invocation arguments under JCS");
      return undefined;
    }),
    mk("pop_iat", 8, () => {
      const iat = st.claims?.iat as number;
      return Math.abs(iat - opts.now) <= lim.popSkew ? undefined : deny(`${SEC}g, §5.3`, "PoP iat is outside the clock tolerance window");
    }),
  ];
}
