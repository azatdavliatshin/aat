import { isObject, jcs, type JsonObject, type JsonValue } from "../json.js";

/**
 * asor-02 §4: scope grammar, constraint vocabulary, subsumption and the
 * step 8 action check. Every function names the section it implements.
 */

// ------------------------------------------------------------ §4.1 scopes

export type ScopeClass = "literal" | "wildcard" | "opaque";

const SEGMENT = "[a-z][a-z0-9_-]*";
const LITERAL = new RegExp(`^${SEGMENT}(\\.${SEGMENT})+$`);
const WILDCARD = new RegExp(`^${SEGMENT}(\\.${SEGMENT})*\\.\\*$`);
// opaque-scope = 1*( %x21 / %x23-29 / %x2B-5B / %x5D-7E ); JS `$` without the m flag does not admit a trailing LF.
const OPAQUE = /^[\x21\x23-\x29\x2B-\x5B\x5D-\x7E]+$/;

/** §4.1: classify by bytes alone, literal, then wildcard, then opaque; undefined = invalid. */
export function classifyScope(s: string): ScopeClass | undefined {
  if (LITERAL.test(s)) return "literal";
  if (WILDCARD.test(s)) return "wildcard";
  if (OPAQUE.test(s)) return "opaque";
  return undefined;
}

/** §4.1: does parent scope `p` cover child scope `c` (both already classified)? */
export function scopeCovers(p: string, pc: ScopeClass, c: string, cc: ScopeClass): boolean {
  if (pc === "wildcard") return cc !== "opaque" && c.startsWith(p.slice(0, -1));
  return p === c; // literal and opaque: byte identity
}

// -------------------------------------------------------- §4.2 constraints

export interface Constraint {
  key: string;
  /** The typed member's name, e.g. "max_lifetime"; may be a type this verifier does not implement. */
  type: string;
  value: JsonValue;
  /** Present for type "rank". */
  order?: string[];
  /** The constraint object as parsed, for byte-identity comparison of unknown types (§4.3). */
  raw: JsonObject;
}

export const NUMERIC_TYPES = ["max", "max_lifetime", "max_subtree", "min"] as const;
const PER_ACTION = ["max", "min", "one_of", "not_one_of", "prefix", "rank"];
const CUMULATIVE = ["max_lifetime", "max_subtree"];
const KNOWN = [...PER_ACTION, ...CUMULATIVE];

/** §4.2: parse one constraint object. Returns a message on malformed input. */
export function parseConstraint(raw: JsonValue): Constraint | string {
  if (!isObject(raw)) return "constraint must be an object";
  if (typeof raw.key !== "string") return "constraint requires a string key";
  const members = Object.keys(raw).filter((m) => m !== "key");
  let type: string;
  if ("rank" in raw) {
    // §4.2: a rank constraint carries "order" in addition to its typed member.
    if (members.length !== 2 || !("order" in raw)) return "rank constraint carries exactly rank and order";
    type = "rank";
  } else {
    if ("order" in raw) return 'only a "rank" constraint carries "order"';
    if (members.length !== 1) return "constraint object is closed: key plus exactly one typed member";
    type = members[0] as string;
  }
  const value = raw[type] as JsonValue;
  const base = { key: raw.key, type, value, raw };
  switch (type) {
    case "max":
    case "max_lifetime":
    case "max_subtree":
    case "min":
      return typeof value === "number" ? base : `${type} must be a number`;
    case "one_of":
    case "not_one_of":
      return Array.isArray(value) ? base : `${type} must be an array`;
    case "prefix":
      return typeof value === "string" ? base : "prefix must be a string";
    case "rank": {
      const order = raw.order;
      if (typeof value !== "string") return "rank must be a string";
      if (!Array.isArray(order) || order.length < 2 || order.some((o) => typeof o !== "string")) {
        return "order must be an array of two or more strings";
      }
      if (new Set(order).size !== order.length) return "order must not repeat a member";
      if (!order.includes(value)) return "rank must be a member of order"; // §4.2
      return { ...base, order: order as string[] };
    }
    default:
      return base; // unknown type: not malformed (§4.2 last paragraph, §4.3)
  }
}

// ------------------------------------------------------ §4 the detail

export interface Detail {
  scopes: Array<{ value: string; cls: ScopeClass }>;
  constraints: Constraint[];
}

/** §4, §4.4: exactly one detail of type agent_delegation with only type/scopes/constraints. */
export function parseDetails(raw: JsonValue | undefined): Detail | string {
  if (!Array.isArray(raw)) return "authorization_details must be an array";
  if (raw.length !== 1) return "a token carries exactly one authorization detail";
  const d = raw[0] as JsonValue;
  if (!isObject(d)) return "authorization detail must be an object";
  if (d.type !== "agent_delegation") return `detail type ${JSON.stringify(d.type)} is not implemented`;
  for (const m of Object.keys(d)) {
    if (m !== "type" && m !== "scopes" && m !== "constraints") return `unknown detail member "${m}"`;
  }
  if (!Array.isArray(d.scopes)) return "scopes must be an array";
  const scopes: Detail["scopes"] = [];
  for (const s of d.scopes) {
    const cls = typeof s === "string" ? classifyScope(s) : undefined;
    if (typeof s !== "string" || !cls) return `invalid scope ${JSON.stringify(s)}`;
    scopes.push({ value: s, cls });
  }
  const rawConstraints = d.constraints ?? [];
  if (!Array.isArray(rawConstraints)) return "constraints must be an array";
  const constraints: Constraint[] = [];
  const seen = new Set<string>();
  for (const rc of rawConstraints) {
    const c = parseConstraint(rc);
    if (typeof c === "string") return c;
    const id = jcs([c.key, c.type]);
    if (seen.has(id)) return `duplicate constraint (${c.key}, ${c.type})`; // §4.2
    seen.add(id);
    constraints.push(c);
  }
  return { scopes, constraints };
}

// ------------------------------------------------------ §4.3 subsumption

const same = (a: JsonValue, b: JsonValue) => jcs(a) === jcs(b);
const isSubset = (a: JsonValue[], b: JsonValue[]) => a.every((x) => b.some((y) => same(x, y)));

/** §4.3 rule 2 for one pair of same (key, type) constraints; true = child admits no more than parent. */
export function constraintNarrows(p: Constraint, c: Constraint): boolean {
  switch (p.type) {
    case "max":
    case "max_lifetime":
    case "max_subtree":
      return (c.value as number) <= (p.value as number);
    case "min":
      return (c.value as number) >= (p.value as number);
    case "one_of":
      return isSubset(c.value as JsonValue[], p.value as JsonValue[]);
    case "not_one_of":
      return isSubset(p.value as JsonValue[], c.value as JsonValue[]);
    case "prefix":
      return (c.value as string).startsWith(p.value as string);
    case "rank": {
      const po = p.order as string[];
      const co = c.order as string[];
      return same(po, co) && co.indexOf(c.value as string) <= po.indexOf(p.value as string);
    }
    default:
      // §4.3: an unimplemented type is subsumed only if byte-identical (JCS) to the parent's.
      return same(p.raw, c.raw);
  }
}

/** §4.3 rules 1-3: undefined if C <= P, else why not. Rules 4 and 5 are checked by the profile. */
export function authorityNarrows(p: Detail, c: Detail): string | undefined {
  for (const cs of c.scopes) {
    if (!p.scopes.some((ps) => scopeCovers(ps.value, ps.cls, cs.value, cs.cls))) {
      return `scope ${cs.value} is not covered by any parent scope`; // rule 1
    }
  }
  for (const pc of p.constraints) {
    const cc = c.constraints.find((x) => x.key === pc.key && x.type === pc.type);
    if (!cc) return `constraint (${pc.key}, ${pc.type}) is absent in the child`; // rule 3
    if (!constraintNarrows(pc, cc)) return `constraint (${pc.key}, ${pc.type}) is wider than the parent's`; // rule 2
  }
  return undefined;
}

// ---------------------------------------------------- §6 step 8, the action

export interface ActionRequest {
  scope: string;
  params?: Readonly<Record<string, unknown>>;
  totals?: Readonly<Record<string, number>>;
}

export interface ActionDenial {
  code: "scope_not_granted" | "ceiling_exceeded" | "unknown_constraint";
  message: string;
}

/**
 * §6 step 8, after the audience check: scope, every per-action constraint
 * against the request only, every cumulative constraint against the supplied
 * totals only. An unknown constraint type or a missing total denies.
 */
export function authorizeAction(leaf: Detail, a: ActionRequest): ActionDenial | undefined {
  const cls = classifyScope(a.scope);
  if (!cls || cls === "wildcard" || !leaf.scopes.some((s) => scopeCovers(s.value, s.cls, a.scope, cls))) {
    return { code: "scope_not_granted", message: `scope ${a.scope} is not granted` };
  }
  for (const c of leaf.constraints) {
    if (!KNOWN.includes(c.type)) return { code: "unknown_constraint", message: `constraint type ${c.type} is not implemented` };
    const exceeded = (why: string): ActionDenial => ({ code: "ceiling_exceeded", message: `(${c.key}, ${c.type}): ${why}` });
    if (CUMULATIVE.includes(c.type)) {
      const total = a.totals?.[c.key];
      if (typeof total !== "number") return exceeded("no running total supplied");
      if (total > (c.value as number)) return exceeded("running total exceeds the bound");
      continue;
    }
    const v = a.params?.[c.key];
    switch (c.type) {
      case "max":
        if (typeof v !== "number" || v > (c.value as number)) return exceeded("value absent or above the ceiling");
        break;
      case "min":
        if (typeof v !== "number" || v < (c.value as number)) return exceeded("value absent or below the floor");
        break;
      case "one_of":
        if (v === undefined || !(c.value as JsonValue[]).some((m) => same(m, v as JsonValue))) return exceeded("value absent or not a member");
        break;
      case "not_one_of":
        if (v === undefined || (c.value as JsonValue[]).some((m) => same(m, v as JsonValue))) return exceeded("value absent or excluded");
        break;
      case "prefix":
        if (typeof v !== "string" || !v.startsWith(c.value as string)) return exceeded("value lacks the prefix");
        break;
      case "rank": {
        const order = c.order as string[];
        const at = typeof v === "string" ? order.indexOf(v) : -1;
        if (at < 0 || at > order.indexOf(c.value as string)) return exceeded("value ranks above the bound");
        break;
      }
    }
  }
  return undefined;
}
