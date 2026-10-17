import type { Outcome } from "./result.js";
import { fail } from "./result.js";

/**
 * Strict JSON for signed tokens. Rejects what asor-02 §3 rejects at parse
 * time: duplicate member names, non-finite numbers, lone surrogates and
 * integers beyond 2^53-1. Objects have a null prototype so that member names
 * such as `__proto__` are ordinary data.
 */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [member: string]: JsonValue };

export type JsonObject = { [member: string]: JsonValue };

export function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const MAX_DEPTH = 64;
const NUMBER = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;

class JsonError extends Error {
  constructor(
    readonly code: "malformed" | "duplicate_member" | "non_finite",
    message: string,
  ) {
    super(message);
  }
}

class Parser {
  private pos = 0;
  constructor(private readonly s: string) {}

  parseDocument(): JsonValue {
    this.ws();
    const v = this.value(0);
    this.ws();
    if (this.pos !== this.s.length) throw new JsonError("malformed", "trailing data after JSON value");
    return v;
  }

  private ws(): void {
    while (" \t\n\r".includes(this.s[this.pos] ?? "x")) this.pos++;
  }

  private value(depth: number): JsonValue {
    if (depth > MAX_DEPTH) throw new JsonError("malformed", "nesting too deep");
    const c = this.s[this.pos];
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') return this.string();
    for (const [lit, val] of [["true", true], ["false", false], ["null", null]] as const) {
      if (this.s.startsWith(lit, this.pos)) {
        this.pos += lit.length;
        return val;
      }
    }
    return this.number();
  }

  private object(depth: number): JsonValue {
    const out: JsonObject = Object.create(null) as JsonObject;
    this.pos++;
    this.ws();
    if (this.s[this.pos] === "}") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.s[this.pos] !== '"') throw new JsonError("malformed", "object member name expected");
      const name = this.string();
      if (Object.hasOwn(out, name)) throw new JsonError("duplicate_member", `duplicate member "${name}"`);
      this.ws();
      if (this.s[this.pos++] !== ":") throw new JsonError("malformed", "':' expected");
      this.ws();
      out[name] = this.value(depth + 1);
      this.ws();
      const c = this.s[this.pos++];
      if (c === "}") return out;
      if (c !== ",") throw new JsonError("malformed", "',' or '}' expected");
    }
  }

  private array(depth: number): JsonValue {
    const out: JsonValue[] = [];
    this.pos++;
    this.ws();
    if (this.s[this.pos] === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth + 1));
      this.ws();
      const c = this.s[this.pos++];
      if (c === "]") return out;
      if (c !== ",") throw new JsonError("malformed", "',' or ']' expected");
    }
  }

  private string(): string {
    this.pos++;
    let out = "";
    for (;;) {
      const c = this.s[this.pos++];
      if (c === undefined) throw new JsonError("malformed", "unterminated string");
      if (c === '"') return out;
      if (c < " ") throw new JsonError("malformed", "unescaped control character in string");
      if (c !== "\\") {
        out += c;
        continue;
      }
      const e = this.s[this.pos++];
      const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (e !== undefined && e in simple) {
        out += simple[e];
      } else if (e === "u") {
        const unit = this.hex4();
        if (unit >= 0xd800 && unit <= 0xdbff) {
          if (this.s[this.pos] !== "\\" || this.s[this.pos + 1] !== "u") throw new JsonError("malformed", "lone surrogate");
          this.pos += 2;
          const low = this.hex4();
          if (low < 0xdc00 || low > 0xdfff) throw new JsonError("malformed", "lone surrogate");
          out += String.fromCharCode(unit, low);
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
          throw new JsonError("malformed", "lone surrogate");
        } else {
          out += String.fromCharCode(unit);
        }
      } else {
        throw new JsonError("malformed", "invalid escape");
      }
    }
  }

  private hex4(): number {
    const h = this.s.slice(this.pos, this.pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) throw new JsonError("malformed", "invalid \\u escape");
    this.pos += 4;
    return parseInt(h, 16);
  }

  private number(): number {
    const m = /^-?[0-9][0-9.eE+-]*/.exec(this.s.slice(this.pos));
    if (!m || !NUMBER.test(m[0])) throw new JsonError("malformed", "invalid value");
    this.pos += m[0].length;
    const n = Number(m[0]);
    if (!Number.isFinite(n)) throw new JsonError("non_finite", "number is not finite");
    // asor-02 §3: an integer beyond 2^53-1 is not represented exactly.
    const isIntegerLiteral = /^-?[0-9]+$/.test(m[0]);
    if (isIntegerLiteral ? BigInt(m[0]) > 2n ** 53n - 1n || BigInt(m[0]) < -(2n ** 53n - 1n) : Number.isInteger(n) && !Number.isSafeInteger(n)) {
      throw new JsonError("malformed", "integer magnitude exceeds 2^53-1");
    }
    return n;
  }
}

/** Parse UTF-8 JSON bytes strictly. Failure codes: malformed, duplicate_member, non_finite. */
export function parseJson(bytes: Uint8Array, section: string): Outcome<JsonValue> {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return fail("malformed", section, "not valid UTF-8");
  }
  try {
    return { ok: true, value: new Parser(text).parseDocument() };
  } catch (e) {
    if (e instanceof JsonError) return fail(e.code, section, e.message);
    throw e;
  }
}

/** RFC 8785 JSON Canonicalization Scheme serialization of a parsed value. */
export function jcs(v: JsonValue): string {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") return Object.is(v, -0) ? "0" : String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  const names = Object.keys(v).sort(); // UTF-16 code unit order, as RFC 8785 §3.2.3 requires
  return `{${names.map((k) => `${JSON.stringify(k)}:${jcs(v[k] as JsonValue)}`).join(",")}}`;
}
