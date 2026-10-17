import { isObject, jcs, parseJson, type JsonObject } from "../json.js";
import { fail, type Outcome } from "../result.js";
import type { Check, CheckResult, ChainContext, Node, Profile } from "../chain.js";
import { verifyHolderBinding } from "../holder.js";
import {
  authorityNarrows,
  authorizeAction,
  parseDetails,
  type Detail,
} from "./asor02-authority.js";

/**
 * draft-asor-wimse-agent-delegation-chain-02. Section tags: "§n" are
 * sections of that draft; "step n" are the steps of its §6.
 *
 * Not implemented (distinct code `not_implemented`): step 7 status-list
 * lookup. A chain whose tokens carry no `status` claim passes step 7
 * vacuously, as the draft allows; a chain that does carry one is denied.
 */

export interface Asor02Token {
  claims: JsonObject;
  detail: Detail;
  sub: string;
  exp: number;
  iat: number;
  nbf?: number;
  delDepth: number;
  delMaxDepth?: number;
  parHash?: string;
  aud: string[];
}

const MALFORMED = "malformed";

function bad(section: string, message: string): Outcome<never> {
  return fail(MALFORMED, section, message);
}

const isNonNegInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const str = (v: unknown): v is string => typeof v === "string";

/** §3 token format, §4 authority: everything a verifier decides before step 1. */
function parse(jws: import("../jws.js").ParsedJws): Outcome<Asor02Token> {
  const utf8 = (b: Uint8Array) => new TextDecoder().decode(b);
  const h = jws.header;
  // §3: both parts MUST be exactly the JCS serialization of what they parse to.
  if (jcs(h) !== utf8(jws.headerBytes)) return fail("non_canonical", "asor-02 §3", "protected header is not JCS");
  if (typeof h.typ !== "string" || !/^(application\/)?at\+jwt$/i.test(h.typ)) {
    return bad("asor-02 §3, RFC 9068 §2.1", 'header typ must be "at+jwt"');
  }
  if (h.kid !== undefined && !str(h.kid)) return bad("asor-02 §3", "kid must be a string");
  const parsed = parseJson(jws.payloadBytes, "asor-02 §3");
  if (!parsed.ok) return parsed;
  const p = parsed.value;
  if (!isObject(p)) return bad("asor-02 §3", "payload must be a JSON object");
  if (jcs(p) !== utf8(jws.payloadBytes)) return fail("non_canonical", "asor-02 §3", "payload is not JCS");

  for (const claim of ["iss", "jti", "client_id", "sub"] as const) {
    if (!str(p[claim])) return bad("asor-02 §3", `${claim} is required and must be a string`);
  }
  for (const claim of ["exp", "iat"] as const) {
    if (typeof p[claim] !== "number") return bad("asor-02 §3", `${claim} is required and must be a number`);
  }
  if (p.nbf !== undefined && typeof p.nbf !== "number") return bad("asor-02 §3", "nbf must be a number");
  // §3 aud: a string, or a non-empty array of strings; absent, null, [] are malformed.
  const aud = typeof p.aud === "string" ? [p.aud] : p.aud;
  if (!Array.isArray(aud) || aud.length === 0 || !aud.every(str)) {
    return bad("asor-02 §3", "aud must be a string or a non-empty array of strings");
  }
  // §3, §7: cnf carries jkt, jwk or x5t#S256.
  const cnf = p.cnf;
  if (!isObject(cnf) || !(str(cnf.jkt) || isObject(cnf.jwk) || str(cnf["x5t#S256"]))) {
    return bad("asor-02 §3, §7", "cnf is required and must carry jkt, jwk or x5t#S256");
  }
  if (!isNonNegInt(p.del_depth)) return bad("asor-02 §3", "del_depth is required, a non-negative integer");
  if (p.del_max_depth !== undefined && !(isNonNegInt(p.del_max_depth) && p.del_max_depth > 0)) {
    return bad("asor-02 §3", "del_max_depth must be a positive integer");
  }
  if (p.par_hash !== undefined && !str(p.par_hash)) return bad("asor-02 §3", "par_hash must be a string");
  const detail = parseDetails(p.authorization_details);
  if (typeof detail === "string") return bad("asor-02 §4, §4.1, §4.2, §4.4", detail);
  return {
    ok: true,
    value: {
      claims: p,
      detail,
      sub: p.sub as string,
      exp: p.exp as number,
      iat: p.iat as number,
      ...(p.nbf !== undefined && { nbf: p.nbf as number }),
      delDepth: p.del_depth,
      ...(p.del_max_depth !== undefined && { delMaxDepth: p.del_max_depth as number }),
      ...(p.par_hash !== undefined && { parHash: p.par_hash as string }),
      aud: aud as string[],
    },
  };
}

type T = Asor02Token;
type N = Node<T>;
const deny = (code: string, section: string, message: string): CheckResult => ({ code, section, message });

/** Step 0: position-dependent claim rules of §3 (a token cannot tell its own position). */
function claimPosition(n: N): Check {
  return {
    name: "claim_position", step: 0, seq: 0, token: n.index,
    run() {
      const c = n.claims;
      if (n.index === 0) {
        if (c.sub === "") return deny(MALFORMED, "asor-02 §3", "DT_0 names no Principal in sub");
        if (c.delMaxDepth === undefined) return deny(MALFORMED, "asor-02 §3", "del_max_depth is REQUIRED in DT_0");
        if (c.parHash !== undefined) return deny(MALFORMED, "asor-02 §3", "par_hash MUST be absent in DT_0");
      } else if (c.parHash === undefined) {
        return deny(MALFORMED, "asor-02 §3", "par_hash is REQUIRED in every DT_i, i > 0");
      }
      return undefined;
    },
  };
}

/** Step 3, depth: DT_i.del_depth == i. */
function depthSequence(n: N): Check {
  return {
    name: "del_depth_sequence", step: 3, seq: 0, token: n.index,
    run: () => n.claims.delDepth === n.index ? undefined : deny("depth_invalid", "asor-02 §6 step 3", `del_depth ${n.claims.delDepth} at position ${n.index}`),
  };
}

/** Step 3, depth: n < DT_0.del_max_depth. */
function chainLength(root: N, ctx: ChainContext<T>): Check {
  return {
    name: "chain_within_del_max_depth", step: 3, seq: 1, token: 0,
    run() {
      const last = ctx.tokens.length - 1;
      return last < (root.claims.delMaxDepth as number) ? undefined : deny("depth_invalid", "asor-02 §6 step 3", `chain length ${last} reaches del_max_depth ${root.claims.delMaxDepth}`);
    },
  };
}

/** Step 3, principal: DT_i.sub identical to DT_0.sub. */
function principalInvariant(n: N, root: N): Check {
  return {
    name: "principal_invariant", step: 3, seq: 2, token: n.index,
    run: () => n.claims.sub === root.claims.sub ? undefined : deny("principal_altered", "asor-02 §3, §6 step 3", "sub differs from DT_0's"),
  };
}

/** Step 4: C <= P under rules 1, 2, 3 (§4.3) and 5 (del_max_depth). */
function authoritySubsumed(parent: N, child: N, ctx: ChainContext<T>): Check {
  return {
    name: "authority_subsumed", step: 4, seq: 0, token: child.index,
    run() {
      const why = authorityNarrows(parent.claims.detail, child.claims.detail);
      if (why) return deny("not_narrower", "asor-02 §4.3, §6 step 4", why);
      if (child.claims.delMaxDepth !== undefined) {
        // Rule 5 against the nearest ancestor that states a bound (DT_0 always does).
        const bound = ctx.tokens.slice(0, child.index).reverse().find((t) => t.claims.delMaxDepth !== undefined)?.claims.delMaxDepth as number;
        if (child.claims.delMaxDepth > bound) return deny("not_narrower", "asor-02 §4.3 rule 5", "del_max_depth raised above the parent's");
      }
      return undefined;
    },
  };
}

/** Step 5: nbf <= now <= exp for the token. */
function validityWindow(n: N, now: number): Check {
  return {
    name: "validity_window", step: 5, seq: 0, token: n.index,
    run: () => (n.claims.nbf === undefined || n.claims.nbf <= now) && now <= n.claims.exp ? undefined : deny("expired", "asor-02 §6 step 5", "token is outside its validity window"),
  };
}

/** Step 5 / §4.3 rule 4: C.exp <= P.exp. */
function monotonicExpiry(parent: N, child: N): Check {
  return {
    name: "monotonic_expiry", step: 5, seq: 1, token: child.index,
    run: () => child.claims.exp <= parent.claims.exp ? undefined : deny("expired", "asor-02 §4.3 rule 4, §6 step 5", "exp exceeds the parent's"),
  };
}

/** Step 7: status lists are not implemented; a status reference cannot be established, so it denies. */
function statusReference(n: N): Check {
  return {
    name: "status_reference", step: 7, seq: 0, token: n.index,
    run: () => n.claims.claims.status === undefined ? undefined : deny("not_implemented", "asor-02 §6 step 7, §8", "token carries a status reference; status-list lookup is not implemented"),
  };
}

export const asor02: Profile<T> = {
  name: "asor-02",
  parse,
  declaredParentHash: (c) => c.parHash,
  tokenChecks: (n, ctx) => [
    claimPosition(n),
    depthSequence(n),
    principalInvariant(n, ctx.tokens[0] as N),
    validityWindow(n, ctx.options.now),
    statusReference(n),
  ],
  rootChecks: (root, ctx) => [chainLength(root, ctx)],
  linkChecks: (parent, child, ctx) => [authoritySubsumed(parent, child, ctx), monotonicExpiry(parent, child)],
  leafChecks(leaf, ctx) {
    const { audience, request } = ctx.options;
    const out: Check[] = [];
    const dpop = request?.dpop;
    if (dpop) {
      out.push({
        name: "holder_binding", step: 6, seq: 0, token: leaf.index,
        run() {
          const why = verifyHolderBinding(leaf.claims.claims.cnf as JsonObject, { ...dpop, accessToken: leaf.jws.compact, now: ctx.options.now });
          return why ? deny("holder_binding_failed", "asor-02 §6 step 6, §7", why) : undefined;
        },
      });
    }
    if (audience !== undefined) {
      out.push({
        name: "audience", step: 8, seq: 0, token: leaf.index,
        run: () => leaf.claims.aud.includes(audience) ? undefined : deny("audience_mismatch", "asor-02 §3, §6 step 8", "aud of DT_n does not name this Enforcement Point"),
      });
      const action = request?.action;
      if (action) {
        out.push({
          name: "action", step: 8, seq: 1, token: leaf.index,
          run() {
            const d = authorizeAction(leaf.claims.detail, { ...action, ...(request?.totals && { totals: request.totals }) });
            return d ? deny(d.code, "asor-02 §4.2, §6 step 8", d.message) : undefined;
          },
        });
      }
    }
    return out;
  },
};
