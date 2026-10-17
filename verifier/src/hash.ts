import { createHash } from "node:crypto";
import { b64urlEncode } from "./encoding.js";

/** SHA-256, base64url without padding (asor-02 §3 `par_hash`; AAT-01 §4.6). */
export function sha256b64u(bytes: Uint8Array): string {
  return b64urlEncode(createHash("sha256").update(bytes).digest());
}

/**
 * RFC 7515 §5.1 JWS Signing Input: the ASCII bytes of
 * `BASE64URL(header) || "." || BASE64URL(payload)` exactly as transmitted.
 */
export function signingInput(compactJws: string): Uint8Array {
  const last = compactJws.lastIndexOf(".");
  if (last < 0) throw new Error("not a compact JWS");
  return new Uint8Array(Buffer.from(compactJws.slice(0, last), "ascii"));
}

/** Commitment a child makes to a parent token instance (asor-02 §5). */
export function parentHash(parentCompactJws: string): string {
  return sha256b64u(signingInput(parentCompactJws));
}
