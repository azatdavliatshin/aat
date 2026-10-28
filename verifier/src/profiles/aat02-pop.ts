import type { Node, VerifyOptions } from "../chain.js";
import { sha256b64u } from "../hash.js";
import { allAdmissible, isExactObject, jcs, parseJsonExact, toPlain, type JsonObject, type JsonValue } from "../json.js";
import { verifyJws } from "../jws.js";
import type { Failure } from "../result.js";
import { toJson } from "./aat01-pop.js";
import { deny, equalCt, headerCheck, integer, split, toParsed, type Aat02Limits, type Aat02Token } from "./aat02.js";

/**
 * AAT-02 §8 step 6b (reading the invocation) and step 7 (PoP JWT, §7.2,
 * §7.3, I6). "§n" are sections of draft-niyikiza-oauth-attenuating-agent-tokens-02.
 */

/**
 * Step 6b, "as written in the invocation": a JSON text is parsed keeping
 * exact numbers, rejecting duplicate member names and inadmissible numbers
 * (§3.4). An already-parsed object cannot carry either fault, so it is only
 * checked to be plain JSON.
 */
export function readInvocation(args: string | Readonly<Record<string, unknown>>): Readonly<Record<string, JsonValue>> | string {
  if (typeof args === "string") {
    const p = parseJsonExact(new TextEncoder().encode(args), "§8 step 6b", { maxDepth: 1024 });
    if (!p.ok) return `invocation arguments: ${p.message}`;
    if (!isExactObject(p.value)) return "invocation arguments are not a JSON object";
    if (!allAdmissible(p.value)) return "invocation arguments contain a number that is not admissible (§3.4)";
    return toPlain(p.value) as JsonObject;
  }
  const v = toJson(args);
  return v !== undefined && typeof v === "object" && v !== null && !Array.isArray(v) ? v : "invocation arguments are not a JSON object";
}

export interface PopInput {
  pop: string;
  tool: string;
  args: Readonly<Record<string, JsonValue>>;
  leaf: Node<Aat02Token>;
  /** This enforcement point's audience identifier (§3.2), for aat_aud. */
  audience?: string;
}

/** Step 7a-7i. Returns the failure, or undefined on success (and then 7i has recorded the jti). */
export function popStep(input: PopInput, opts: VerifyOptions, lim: Aat02Limits, maxDepth: number): Failure | undefined {
  const leaf = input.leaf;
  const at = leaf.index;
  const seg = split(input.pop);
  if (!seg) return deny("7a", "I6", "PoP JWT is not a compact JWS", at);
  const h = headerCheck(seg, "aat-pop+jwt", opts);
  if (!h.ok) return deny("7a", h.code, `PoP JWT: ${h.message}`, at);
  const jws = toParsed(seg, h.value);
  if (!seg.signature || !verifyJws(jws, { alg: "Ed25519", publicKey: leaf.claims.key })) {
    return deny("7b", "I6", "PoP signature does not verify under leaf.cnf.jwk", at);
  }
  const parsed = parseJsonExact(seg.payloadBytes, "§8 step 7b", { maxDepth });
  if (!parsed.ok) return deny("7b", "I6", `PoP JWT claims: ${parsed.message}`, at);
  // §7.2 (-02): the PoP payload need not be JCS-canonical; it is read as presented.
  const c = parsed.value;
  if (!isExactObject(c)) return deny("7b", "I6", "PoP payload is not a JSON object", at);

  for (const m of ["jti", "aat_id", "aat_hash", "aat_tool"] as const) {
    const v = c[m];
    if (typeof v !== "string" || v === "") return deny("7c", "I6", `PoP ${m} must be a non-empty string`, at);
  }
  const iat = integer(c.iat);
  if (iat === undefined) return deny("7c", "I6", "PoP iat must be a NumericDate with no fraction or exponent (§3.2)", at);
  if (!isExactObject(c.hta)) return deny("7c", "I6", "PoP hta must be present and a JSON object", at);
  if (c.aat_id !== leaf.claims.jti) return deny("7c", "I6", "aat_id does not equal the leaf jti", at);
  if (!equalCt(c.aat_hash as string, sha256b64u(leaf.jws.signingInput))) return deny("7c", "I6", "aat_hash does not bind the presented leaf", at);

  if (Object.hasOwn(c, "aat_aud")) {
    // §7.2: "When present, an enforcement point MUST reject a PoP JWT whose aat_aud does not identify itself."
    if (typeof c.aat_aud !== "string" || input.audience === undefined || c.aat_aud !== input.audience) {
      return deny("7d", "I6", "aat_aud does not identify this enforcement point", at);
    }
  } else if (lim.requirePopAudience) {
    return deny("7d", "I6", "aat_aud is required by this enforcement point", at);
  }

  if (c.aat_tool !== input.tool) return deny("7e", "I6", "aat_tool does not equal the invoked tool (§3.3.1)", at);

  if (!allAdmissible(c.hta)) return deny("7f", "I6", "hta contains a number that is not admissible (§3.4)", at);
  if (jcs(toPlain(c.hta)) !== jcs(input.args as JsonObject)) return deny("7f", "I6", "hta does not equal the invocation arguments under JCS", at);

  if (Math.abs(iat - opts.now) > lim.popSkew) return deny("7g", "I6", "PoP iat is outside the clock tolerance window", at);

  if (lim.popNonces !== undefined) {
    if (typeof c.nonce !== "string" || !lim.popNonces.includes(c.nonce)) {
      return deny("7h", "nonce", "PoP nonce is absent or not one this enforcement point issued and still accepts", at);
    }
  }

  // Step 7i: check-and-record, after every other check has passed.
  if (lim.popJtiCache !== undefined) {
    const jti = c.jti as string;
    if (lim.popJtiCache.has(jti)) return deny("7i", "replay", "PoP jti has already been accepted inside the window", at);
    lim.popJtiCache.add(jti);
  }
  return undefined;
}
