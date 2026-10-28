import { allAdmissible, ExactNumber, isExactObject, toPlain, type ExactValue, type JsonValue } from "../json.js";
import { satisfies, subsumesWith, type AllRule, type Constraint } from "./aat01-constraints.js";

/**
 * AAT-02 argument constraints. "§n" are sections of
 * draft-niyikiza-oauth-attenuating-agent-tokens-02; "step 4p2" is a step of
 * its §8 algorithm.
 *
 * Shared with -01 (aat01-constraints.ts), where -02 kept the rule: the value
 * model, the check predicate (§3.4) and every §4.5 table row except `all`.
 * Forked here: well-formedness (§3.4, new list), the `optional` member and the
 * `"*"` entry (§3.3), map normalization and the key rules (§4.5, step 4p2-4p4),
 * and `all` subsumption (one derived clause may satisfy several parent clauses).
 */

/** One constraint-map entry: the constraint and its top-level `optional` flag (§3.3). */
export interface Entry {
  c: Constraint;
  optional: boolean;
}

/** Argument name -> entry; `"*"` is the unnamed-argument entry (§3.3). */
export type ArgMap = ReadonlyMap<string, Entry>;
export type ToolMap = ReadonlyMap<string, ArgMap>;

export const STAR = "*";

export type ConstraintError = { kind: "malformed" | "unknown_constraint" | "constraint_depth"; message: string };

/** Members each core type defines (§3.4, Table 2). */
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

const num = (v: ExactValue | undefined): v is ExactNumber => v instanceof ExactNumber;

/**
 * §3.4 well-formedness of one constraint, recursively. `top` is true for a
 * constraint-map entry (where `optional` may appear). Numbers are checked for
 * admissibility on the raw value, before anything is reduced to a double.
 */
function parseOne(raw: ExactValue, top: boolean): { c: Constraint; optional: boolean } | ConstraintError {
  const bad = (message: string): ConstraintError => ({ kind: "malformed", message });
  if (!isExactObject(raw)) return bad("a constraint must be an object");
  const t = raw.constraint_type;
  if (typeof t !== "string") return bad("constraint_type is required and must be a string");
  const own = MEMBERS[t];
  // §3.4, §5.2: a type this enforcement point does not implement is fail-closed.
  if (!own) return { kind: "unknown_constraint", message: `unrecognized constraint_type ${JSON.stringify(t)}` };
  for (const m of Object.keys(raw)) {
    if (m === "constraint_type" || own.includes(m)) continue;
    if (m === "optional") {
      // §3.3, §3.4: optional only on a top-level constraint-map entry, and a boolean.
      if (!top) return bad(`${t}: optional may appear only on a top-level constraint-map entry`);
      continue;
    }
    return bad(`${t}: member "${m}" is not defined for this type`);
  }
  if (raw.optional !== undefined && typeof raw.optional !== "boolean") return bad("optional must be a boolean");
  const optional = raw.optional === true;
  // §3.4: "every number in it is admissible".
  if (!allAdmissible(raw)) return bad(`${t}: contains a number that is not admissible (§3.4)`);
  const arr = (name: string): readonly ExactValue[] | ConstraintError => {
    const v = raw[name];
    return Array.isArray(v) ? v : bad(`${t}: ${name} must be an array`);
  };
  const plain = (vs: readonly ExactValue[]): JsonValue[] => vs.map(toPlain);
  const done = (c: Constraint) => ({ c, optional });
  switch (t) {
    case "exact": {
      const v = raw.value;
      if (!(typeof v === "string" || typeof v === "boolean" || v === null || num(v))) {
        return bad("exact: value must be a string, number, boolean or null");
      }
      return done({ type: "exact", value: num(v) ? v.value : v });
    }
    case "range": {
      for (const m of ["min", "max"] as const) if (raw[m] !== undefined && !num(raw[m])) return bad(`range: ${m} must be a number`);
      for (const [flag, bound] of [["min_inclusive", "min"], ["max_inclusive", "max"]] as const) {
        if (raw[flag] === undefined) continue;
        if (typeof raw[flag] !== "boolean") return bad(`range: ${flag} must be a boolean`);
        if (raw[bound] === undefined) return bad(`range: ${flag} may appear only with ${bound}`);
      }
      const min = num(raw.min) ? raw.min.value : undefined;
      const max = num(raw.max) ? raw.max.value : undefined;
      if (min !== undefined && max !== undefined && min > max) return bad("range: min is greater than max");
      return done({
        type: "range",
        ...(min !== undefined && { min }),
        ...(max !== undefined && { max }),
        minInclusive: raw.min_inclusive !== false,
        maxInclusive: raw.max_inclusive !== false,
      });
    }
    case "one_of": {
      const v = arr("values");
      if ("kind" in v) return v;
      if (v.length === 0) return bad("one_of: values must be a non-empty array");
      return done({ type: "one_of", values: plain(v) });
    }
    case "not_one_of": {
      const v = arr("excluded");
      return "kind" in v ? v : done({ type: "not_one_of", excluded: plain(v) });
    }
    case "contains": {
      const v = arr("required");
      return "kind" in v ? v : done({ type: "contains", required: plain(v) });
    }
    case "subset": {
      const v = arr("allowed");
      return "kind" in v ? v : done({ type: "subset", allowed: plain(v) });
    }
    case "wildcard":
      return done({ type: "wildcard" });
    default: {
      const v = arr("constraints");
      if ("kind" in v) return v;
      // §4.5, step 3n/4o: an empty all or any is invalid in every position.
      if (v.length === 0) return bad(`${t}: constraints must not be empty`);
      const clauses: Constraint[] = [];
      for (const k of v) {
        const p = parseOne(k, false);
        if ("kind" in p) return p;
        clauses.push(p.c);
      }
      return done({ type: t as "all" | "any", clauses });
    }
  }
}

/** §3.4: a leaf constraint has depth 1; all/any one more than the deepest clause. */
export function depthOf(c: Constraint): number {
  return c.type === "all" || c.type === "any" ? 1 + Math.max(...c.clauses.map(depthOf)) : 1;
}

/**
 * Steps 3m/4n (shape of `tools`) are the caller's; this is step 3n/4o for one
 * tool's constraint map: depth, implemented type, well-formedness (§3.4) and
 * the `"*"` entry rule (§3.3).
 */
export function parseArgMap(raw: ExactValue, maxConstraintDepth: number): ArgMap | ConstraintError {
  if (!isExactObject(raw)) return { kind: "malformed", message: "a constraint map must be an object" };
  const out = new Map<string, Entry>();
  for (const [arg, rc] of Object.entries(raw)) {
    const e = parseOne(rc, true);
    if ("kind" in e) return { ...e, message: `${JSON.stringify(arg)}: ${e.message}` };
    if (depthOf(e.c) > maxConstraintDepth) {
      return { kind: "constraint_depth", message: `${JSON.stringify(arg)}: constraint tree deeper than MAX_CONSTRAINT_DEPTH ${maxConstraintDepth}` };
    }
    // §3.3: the "*" value MUST be a wildcard constraint without an optional member.
    if (arg === STAR && (e.c.type !== "wildcard" || (isExactObject(rc) && rc.optional !== undefined))) {
      return { kind: "malformed", message: '"*" must be a wildcard constraint without optional' };
    }
    out.set(arg, e);
  }
  return out;
}

const WILDCARD: Entry = { c: { type: "wildcard" }, optional: false };

/** §3.3: an empty constraint map is {"*": {"constraint_type": "wildcard"}}. */
export function normalize(m: ArgMap): ArgMap {
  return m.size === 0 ? new Map([[STAR, WILDCARD]]) : m;
}

/** §4.5 `all` (-02): every parent clause subsumes at least one derived clause; a derived clause may be reused. */
const allWithReuse: AllRule = (parents, derived, sub) => parents.every((p) => derived.some((d) => sub(d, p)));

/** `child ⊑ parent` under the -02 §4.5 table. */
export function subsumes02(child: Constraint, parent: Constraint): boolean {
  return subsumesWith(child, parent, allWithReuse);
}

/** Step 4p2: the key rules of §4.5 on normalized maps. Returns a message on failure. */
export function keyRules(parentMap: ArgMap, childMap: ArgMap): string | undefined {
  const p = normalize(parentMap);
  const c = normalize(childMap);
  const pStar = p.has(STAR);
  const cStar = c.has(STAR);
  if (cStar && !pStar) return 'the derived map contains "*" but the parent map does not';
  for (const k of c.keys()) {
    if (k !== STAR && !p.has(k) && !pStar) return `argument ${JSON.stringify(k)} is neither named nor admitted by "*" in the parent`;
  }
  for (const [k, e] of p) {
    if (k === STAR || c.has(k)) continue;
    if (!e.optional) return `argument ${JSON.stringify(k)} is required by the parent and omitted`;
    if (cStar) return `argument ${JSON.stringify(k)} is omitted while "*" is kept, so it returns under "*"`;
  }
  return undefined;
}

/** Step 4p3: a key the parent requires stays required. */
export function requiredKept(parentMap: ArgMap, childMap: ArgMap): string | undefined {
  const p = normalize(parentMap);
  for (const [k, e] of normalize(childMap)) {
    if (k === STAR) continue;
    const pe = p.get(k);
    if (pe && !pe.optional && e.optional) return `argument ${JSON.stringify(k)} is required by the parent and optional here`;
  }
  return undefined;
}

/** Step 4p4: each child constraint is subsumed by the parent's (or the parent's "*"), ignoring optional. */
export function constraintsNarrow(parentMap: ArgMap, childMap: ArgMap): string | undefined {
  const p = normalize(parentMap);
  for (const [k, e] of normalize(childMap)) {
    const pe = p.get(k) ?? p.get(STAR);
    if (!pe) return `argument ${JSON.stringify(k)} has no parent constraint`; // excluded by 4p2
    if (!subsumes02(e.c, pe.c)) return `${JSON.stringify(k)}: ${e.c.type} is not subsumed by parent ${pe.c.type}`;
  }
  return undefined;
}

/**
 * Step 6b, after the caller has checked duplicate members and admissibility:
 * closed-world evaluation of `args` against the tool's normalized map.
 */
export function authorizeArgs(map: ArgMap, args: Readonly<Record<string, JsonValue>>): string | undefined {
  const m = normalize(map);
  for (const [name, value] of Object.entries(args)) {
    // §3.3: an argument literally named "*" is treated as unnamed.
    const e = name !== STAR ? m.get(name) : undefined;
    const use = e ?? m.get(STAR);
    if (!use) return `argument ${JSON.stringify(name)} is not named and the map has no "*" (closed world)`;
    if (!satisfies(use.c, value)) return `argument ${JSON.stringify(name)} violates its ${use.c.type} constraint`;
  }
  for (const [name, e] of m) {
    if (name === STAR || e.optional) continue;
    if (!Object.hasOwn(args, name)) return `required argument ${JSON.stringify(name)} is absent`;
  }
  return undefined;
}
