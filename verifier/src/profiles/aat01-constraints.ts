import { isObject, jcs, type JsonObject, type JsonValue } from "../json.js";

/**
 * AAT-01 argument constraints: value model (§3.4, Table 2), check predicate
 * (§3.4, §7 step 6b) and subsumption (§4.5). "§n" are sections of
 * draft-niyikiza-oauth-attenuating-agent-tokens-01.
 *
 * Reading rule where the draft is silent: the strictest one, i.e. a pair of
 * constraints is accepted as attenuation only when §4.5 names it ("Any
 * (parent constraint type, derived constraint type) pair not explicitly
 * permitted ... MUST be rejected"). Each such place is tagged
 * `draft unspecified` and listed in docs/analysis/draft-observations.md.
 */

export type Scalar = string | number | boolean;

export type Constraint =
  // `null` only in aat-02 (-02 §3.4 "string, number, boolean, or null"); the -01 parser below never produces it.
  | { type: "exact"; value: Scalar | null }
  | { type: "range"; min?: number; max?: number; minInclusive: boolean; maxInclusive: boolean }
  | { type: "one_of"; values: readonly JsonValue[] }
  | { type: "not_one_of"; excluded: readonly JsonValue[] }
  | { type: "contains"; required: readonly JsonValue[] }
  | { type: "subset"; allowed: readonly JsonValue[] }
  | { type: "wildcard" }
  | { type: "all"; clauses: readonly Constraint[] }
  | { type: "any"; clauses: readonly Constraint[] };

export type ConstraintError = { kind: "malformed" | "unknown_constraint"; message: string };

const eq = (a: JsonValue, b: JsonValue): boolean => jcs(a) === jcs(b);
const has = (set: readonly JsonValue[], v: JsonValue): boolean => set.some((x) => eq(x, v));
/** Set inclusion by JSON equality. */
const includes = (outer: readonly JsonValue[], inner: readonly JsonValue[]): boolean => inner.every((v) => has(outer, v));

const MEMBERS: Record<string, readonly string[]> = {
  exact: ["value"],
  range: ["min", "max", "min_inclusive", "max_inclusive"],
  one_of: ["values"],
  not_one_of: ["excluded"],
  contains: ["required"],
  subset: ["allowed"],
  wildcard: [],
  all: ["constraints"],
  any: ["constraints"],
};

/** Parse one constraint object (§3.4). Unknown `constraint_type` is fail-closed (§3.4). */
export function parseConstraint(raw: JsonValue, depth = 0): Constraint | ConstraintError {
  const bad = (message: string): ConstraintError => ({ kind: "malformed", message });
  if (!isObject(raw)) return bad("a constraint must be an object");
  const t = raw.constraint_type;
  if (typeof t !== "string") return bad("constraint_type is required and must be a string");
  const allowed = MEMBERS[t];
  if (!allowed) return { kind: "unknown_constraint", message: `unrecognized constraint_type ${JSON.stringify(t)}` };
  // draft unspecified: members outside Table 2 for a core type; rejected, not ignored (§3.4 is silent).
  for (const m of Object.keys(raw)) {
    if (m !== "constraint_type" && !allowed.includes(m)) return bad(`${t}: unexpected member "${m}"`);
  }
  const arr = (name: string): readonly JsonValue[] | ConstraintError => {
    const v = raw[name];
    return Array.isArray(v) ? v : bad(`${t}: ${name} must be an array`);
  };
  switch (t) {
    case "exact": {
      const v = raw.value;
      // draft unspecified: "any scalar" is read as string, number or boolean; null is not a scalar here.
      if (typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") return bad("exact: value must be a string, number or boolean");
      return { type: "exact", value: v };
    }
    case "range": {
      for (const m of ["min", "max"] as const) if (raw[m] !== undefined && typeof raw[m] !== "number") return bad(`range: ${m} must be a number`);
      for (const m of ["min_inclusive", "max_inclusive"] as const) if (raw[m] !== undefined && typeof raw[m] !== "boolean") return bad(`range: ${m} must be a boolean`);
      return {
        type: "range",
        ...(raw.min !== undefined && { min: raw.min as number }),
        ...(raw.max !== undefined && { max: raw.max as number }),
        minInclusive: raw.min_inclusive !== false, // §3.4: both default to true
        maxInclusive: raw.max_inclusive !== false,
      };
    }
    case "one_of": {
      const v = arr("values");
      return "kind" in v ? v : { type: "one_of", values: v };
    }
    case "not_one_of": {
      const v = arr("excluded");
      return "kind" in v ? v : { type: "not_one_of", excluded: v };
    }
    case "contains": {
      const v = arr("required");
      return "kind" in v ? v : { type: "contains", required: v };
    }
    case "subset": {
      const v = arr("allowed");
      return "kind" in v ? v : { type: "subset", allowed: v };
    }
    case "wildcard":
      return { type: "wildcard" };
    default: {
      // all / any
      const v = arr("constraints");
      if ("kind" in v) return v;
      // draft unspecified: an empty clause list (§4.5 only forbids it for a derived `any`); rejected for both types.
      if (v.length === 0) return bad(`${t}: constraints must not be empty`);
      const clauses: Constraint[] = [];
      for (const c of v) {
        const p = parseConstraint(c, depth + 1);
        if ("kind" in p) return p;
        clauses.push(p);
      }
      return { type: t as "all" | "any", clauses };
    }
  }
}

/** Nesting depth of a constraint tree: a leaf constraint has depth 1 (§3.4 MAX_CONSTRAINT_DEPTH). */
export function constraintDepth(c: Constraint): number {
  return c.type === "all" || c.type === "any" ? 1 + Math.max(...c.clauses.map(constraintDepth)) : 1;
}

/** Check predicate (§3.4): does the argument value satisfy the constraint? */
export function satisfies(c: Constraint, value: JsonValue): boolean {
  switch (c.type) {
    case "exact":
      return eq(c.value, value);
    case "range": {
      if (typeof value !== "number") return false;
      if (c.min !== undefined && !(c.minInclusive ? value >= c.min : value > c.min)) return false;
      if (c.max !== undefined && !(c.maxInclusive ? value <= c.max : value < c.max)) return false;
      return true;
    }
    case "one_of":
      return has(c.values, value);
    case "not_one_of":
      return !has(c.excluded, value);
    case "contains":
      return Array.isArray(value) && includes(value, c.required);
    case "subset":
      return Array.isArray(value) && includes(c.allowed, value);
    case "wildcard":
      return true;
    case "all":
      return c.clauses.every((k) => satisfies(k, value));
    case "any":
      return c.clauses.some((k) => satisfies(k, value));
  }
}

type Range = Extract<Constraint, { type: "range" }>;

/** A number lies in the parent range (exact ⊑ range, §4.5). */
function inRange(v: number, r: Range): boolean {
  return satisfies(r, v);
}

/** Is the lower (or upper) bound of `d` at least as restrictive as `p`'s? §4.5 range. */
function boundNarrows(d: number | undefined, dInc: boolean, p: number | undefined, pInc: boolean, side: "min" | "max"): boolean {
  if (p === undefined) return true; // a missing parent bound is unbounded
  if (d === undefined) return false; // a missing derived bound is valid only if the parent's is also missing
  if (d === p) return pInc || !dInc; // same value: exclusive is tighter, inclusive over exclusive widens
  return side === "min" ? d > p : d < p;
}

/** How a derived `all` is matched to a parent `all` (the one rule -01 and -02 decide differently). */
export type AllRule = (parents: readonly Constraint[], derived: readonly Constraint[], sub: (c: Constraint, p: Constraint) => boolean) => boolean;

/** One-to-one clause assignment with backtracking, as in the §4.5 pseudocode. */
function matchAll(parents: readonly Constraint[], derived: readonly Constraint[]): boolean {
  const used = new Set<number>();
  const go = (idx: number): boolean => {
    if (idx === parents.length) return true;
    for (const [i, d] of derived.entries()) {
      if (used.has(i) || !subsumes(d, parents[idx] as Constraint)) continue;
      used.add(i);
      if (go(idx + 1)) return true;
      used.delete(i);
    }
    return false;
  };
  return go(0);
}

/**
 * `child ⊑ parent` (§4.5): every value that satisfies `child` satisfies
 * `parent`, restricted to the pairs the draft names. Pairs it does not name
 * are rejected.
 */
export function subsumes(child: Constraint, parent: Constraint): boolean {
  return subsumesWith(child, parent, (p, d) => matchAll(p, d));
}

/** `subsumes` with the `all` matching rule as a parameter; every other pair as -01 §4.5 names it. */
export function subsumesWith(child: Constraint, parent: Constraint, allRule: AllRule): boolean {
  const sub = (c: Constraint, p: Constraint): boolean => subsumesWith(c, p, allRule);
  // §4.5 wildcard: "Any other constraint type subsumes a parent wildcard"; a derived wildcard needs a wildcard parent.
  if (parent.type === "wildcard") return true;
  switch (child.type) {
    case "exact": {
      // §4.5 exact: parent exact (identical), range (number inside), one_of (member), wildcard (above).
      // Every other parent type is an invalid cross-type target, including not_one_of, contains, subset, all, any.
      if (parent.type === "exact") return eq(child.value, parent.value);
      if (parent.type === "range") return typeof child.value === "number" && inRange(child.value, parent);
      if (parent.type === "one_of") return has(parent.values, child.value);
      return false;
    }
    case "range": {
      if (parent.type !== "range") return false; // draft unspecified: range under one_of/any/all is not named
      return (
        boundNarrows(child.min, child.minInclusive, parent.min, parent.minInclusive, "min") &&
        boundNarrows(child.max, child.maxInclusive, parent.max, parent.maxInclusive, "max")
      );
    }
    case "one_of":
      // §4.5 one_of: subset of the parent's values. draft unspecified: one_of under a range parent is not named, so rejected.
      return parent.type === "one_of" && includes(parent.values, child.values);
    case "not_one_of":
      // §4.5 not_one_of: superset of the parent's excluded set; against a parent one_of it MUST be rejected.
      return parent.type === "not_one_of" && includes(child.excluded, parent.excluded);
    case "contains":
      return parent.type === "contains" && includes(child.required, parent.required);
    case "subset":
      return parent.type === "subset" && includes(parent.allowed, child.allowed);
    case "wildcard":
      return false; // parent is not a wildcard here
    case "all":
      // draft unspecified: a derived `all` against a non-`all` parent (other than wildcard) is not named, so rejected.
      return parent.type === "all" && allRule(parent.clauses, child.clauses, sub);
    case "any":
      // §4.5 any: every derived clause is subsumed by at least one parent clause (cross-type clauses allowed).
      return parent.type === "any" && child.clauses.every((d) => parent.clauses.some((p) => sub(d, p)));
  }
}

/** Convenience for tests and vectors: the raw JSON object of a constraint. */
export type RawConstraint = JsonObject;
