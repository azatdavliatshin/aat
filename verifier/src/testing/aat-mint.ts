/** Test-only minting of AAT-01 chains and PoP JWTs. Not exported from the package entry point. */
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, type KeyObject } from "node:crypto";
import { b64urlEncode } from "../encoding.js";
import { parentHash } from "../hash.js";
import { jcs, type JsonObject, type JsonValue } from "../json.js";
import { thumbprintUri } from "../profiles/aat01.js";
import { signJws, signRaw, type SigningKey } from "./sign.js";

export interface Holder {
  privateKey: KeyObject;
  publicKey: KeyObject;
  jwk: JsonObject;
}

function holderOf(privateKey: KeyObject): Holder {
  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: "jwk" }) as JsonObject;
  return { privateKey, publicKey, jwk: { kty: "OKP", crv: "Ed25519", x: jwk.x as string } };
}

export function newHolder(): Holder {
  return holderOf(generateKeyPairSync("ed25519").privateKey);
}

/** Ed25519 key from a 32-byte seed (hex), for deterministic vectors. */
export function holderFromSeed(seedHex: string): Holder {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
  return holderOf(createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
}

const signing = (h: Holder): SigningKey => ({ alg: "EdDSA", privateKey: h.privateKey });

export type Tools = Record<string, Record<string, JsonValue>>;

/** Claim overrides: a value replaces the computed one, `undefined` removes the claim. */
export type Override = Record<string, JsonValue | undefined>;

export interface MintedToken {
  compact: string;
  claims: JsonObject;
  holder: Holder;
}

function apply(claims: JsonObject, override: Override): JsonObject {
  const out = { ...claims };
  for (const [k, v] of Object.entries(override)) {
    if (v === undefined) delete out[k];
    else out[k] = v;
  }
  return out;
}

export interface RootSpec {
  anchor: Holder;
  holder?: Holder;
  iss?: string;
  jti?: string;
  iat: number;
  exp: number;
  maxDepth?: number;
  tools?: Tools;
  override?: Override;
  header?: Record<string, JsonValue>;
}

export function mintRoot(spec: RootSpec): MintedToken {
  const holder = spec.holder ?? newHolder();
  const claims = apply(
    {
      jti: spec.jti ?? randomUUID(),
      iss: spec.iss ?? "https://auth.example.com",
      iat: spec.iat,
      exp: spec.exp,
      del_depth: 0,
      del_max_depth: spec.maxDepth ?? 3,
      cnf: { jwk: holder.jwk },
      authorization_details: [{ type: "attenuating_agent_token", tools: (spec.tools ?? {}) as JsonValue }],
    },
    spec.override ?? {},
  );
  return { compact: signJws(claims, signing(spec.anchor), spec.header), claims, holder };
}

export interface DeriveSpec {
  parent: MintedToken;
  /** Key that signs; defaults to the parent's holder key (I1). */
  signer?: Holder;
  holder?: Holder;
  jti?: string;
  iat?: number;
  exp?: number;
  maxDepth?: number;
  tools?: Tools;
  override?: Override;
  header?: Record<string, JsonValue>;
  /** Commit to this token instead of the parent (I5 violations). */
  parHashOf?: string;
}

export function derive(spec: DeriveSpec): MintedToken {
  const p = spec.parent.claims;
  const signer = spec.signer ?? spec.parent.holder;
  const holder = spec.holder ?? newHolder();
  const claims = apply(
    {
      jti: spec.jti ?? randomUUID(),
      iss: thumbprintUri(signer.jwk),
      iat: spec.iat ?? (p.iat as number),
      exp: spec.exp ?? (p.exp as number),
      del_depth: (p.del_depth as number) + 1,
      del_max_depth: spec.maxDepth ?? (p.del_max_depth as number),
      par_hash: parentHash(spec.parHashOf ?? spec.parent.compact),
      cnf: { jwk: holder.jwk },
      authorization_details: [{ type: "attenuating_agent_token", tools: (spec.tools ?? (p.authorization_details as JsonObject[])[0]?.tools ?? {}) as JsonValue }],
    },
    spec.override ?? {},
  );
  return { compact: signJws(claims, signing(signer), spec.header), claims, holder };
}

export interface PopSpec {
  holder: Holder;
  aatId: string;
  tool: string;
  args: JsonValue;
  iat: number;
  aud?: string;
  jti?: string;
  override?: Override;
  header?: Record<string, JsonValue>;
  /** Serialize with plain JSON.stringify instead of JCS (§5.2 violation). */
  nonCanonical?: boolean;
}

export function mintPop(spec: PopSpec): string {
  const claims = apply(
    {
      jti: spec.jti ?? randomUUID(),
      iat: spec.iat,
      aat_id: spec.aatId,
      aat_tool: spec.tool,
      ...(spec.aud !== undefined && { aat_aud: spec.aud }),
      hta: spec.args,
    },
    spec.override ?? {},
  );
  if (spec.nonCanonical) {
    const h = jcs({ alg: "EdDSA", typ: "JWT", ...spec.header });
    return signRaw(new Uint8Array(Buffer.from(h)), new Uint8Array(Buffer.from(JSON.stringify(claims) + " ")), signing(spec.holder));
  }
  return signJws(claims, signing(spec.holder), { typ: "JWT", ...spec.header });
}

export interface ChainSpec {
  depth: number;
  now?: number;
  tools?: Tools;
  /** Per-link tools for derived tokens (index 0 = first derived); default: unchanged. */
  linkTools?: (Tools | undefined)[];
  /** Per-link overrides (index 0 = root). */
  overrides?: (Override | undefined)[];
  lifetime?: number;
  maxDepth?: number;
  /** Deterministic inputs for vectors: trust anchor, holder key per token, jti per token. */
  anchor?: Holder;
  holders?: Holder[];
  jtis?: string[];
}

export interface Chain {
  anchor: Holder;
  tokens: MintedToken[];
  compact: string[];
  leaf: MintedToken;
  now: number;
}

/** A valid chain of `depth + 1` tokens: lifetimes nest, iat is non-decreasing, `now` is inside every window. */
export function mintChain(spec: ChainSpec): Chain {
  const now = spec.now ?? 1_000_000;
  const life = spec.lifetime ?? 1000;
  const anchor = spec.anchor ?? newHolder();
  const root = mintRoot({
    anchor,
    ...(spec.holders?.[0] && { holder: spec.holders[0] }),
    ...(spec.jtis?.[0] && { jti: spec.jtis[0] }),
    iat: now - 10 * (spec.depth + 1),
    exp: now - 10 * (spec.depth + 1) + life,
    maxDepth: spec.maxDepth ?? Math.max(spec.depth, 3),
    ...(spec.tools && { tools: spec.tools }),
    ...(spec.overrides?.[0] && { override: spec.overrides[0] }),
  });
  const tokens = [root];
  for (let i = 1; i <= spec.depth; i++) {
    const parent = tokens[i - 1] as MintedToken;
    tokens.push(
      derive({
        parent,
        ...(spec.holders?.[i] && { holder: spec.holders[i] as Holder }),
        ...(spec.jtis?.[i] && { jti: spec.jtis[i] as string }),
        iat: (parent.claims.iat as number) + 10,
        exp: (parent.claims.exp as number) - 1,
        ...(spec.linkTools?.[i - 1] && { tools: spec.linkTools[i - 1] as Tools }),
        ...(spec.overrides?.[i] && { override: spec.overrides[i] as Override }),
      }),
    );
  }
  return { anchor, tokens, compact: tokens.map((t) => t.compact), leaf: tokens[tokens.length - 1] as MintedToken, now };
}

export const b64u = b64urlEncode;
