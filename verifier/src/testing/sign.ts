/** Test-only signing helpers. Not exported from the package entry point. */
import { createHmac, sign as cryptoSign, type KeyObject } from "node:crypto";
import { b64urlEncode } from "../encoding.js";
import { jcs, type JsonValue } from "../json.js";
import type { JwsAlg } from "../jws.js";

export type SigningKey = { alg: "EdDSA"; privateKey: KeyObject } | { alg: "HS256"; secret: Uint8Array };

function sig(input: Uint8Array, key: SigningKey): Uint8Array {
  if (key.alg === "EdDSA") return new Uint8Array(cryptoSign(null, input, key.privateKey));
  return new Uint8Array(createHmac("sha256", key.secret).update(input).digest());
}

/** Sign already-serialized header and payload bytes. */
export function signRaw(headerBytes: Uint8Array, payloadBytes: Uint8Array, key: SigningKey): string {
  const input = `${b64urlEncode(headerBytes)}.${b64urlEncode(payloadBytes)}`;
  return `${input}.${b64urlEncode(sig(new Uint8Array(Buffer.from(input, "ascii")), key))}`;
}

/** Sign JCS-serialized objects; `alg` is taken from the key unless `header` overrides it. */
export function signJws(payload: JsonValue, key: SigningKey, header: Record<string, JsonValue> = {}): string {
  const alg: JwsAlg = key.alg;
  const h = jcs({ alg, typ: "at+jwt", ...header });
  return signRaw(new Uint8Array(Buffer.from(h, "utf8")), new Uint8Array(Buffer.from(jcs(payload), "utf8")), key);
}
