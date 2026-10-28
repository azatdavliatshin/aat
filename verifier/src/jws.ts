import { createHmac, timingSafeEqual, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { b64urlDecodeStrict } from "./encoding.js";
import { isObject, parseJson, type JsonObject } from "./json.js";
import { fail, type Outcome } from "./result.js";

/**
 * Compact JWS (RFC 7515 §7.1). Only the algorithms below are known.
 * "Ed25519" is the fully-specified name (RFC 9864) that aat-02 requires;
 * "EdDSA" stays for asor-02 and aat-01. `parseJws` admits EdDSA and HS256
 * only; the aat-02 profile reads its headers itself (-02 §8 steps 3a, 4a, 7a).
 */
export type JwsAlg = "EdDSA" | "Ed25519" | "HS256"; // HS256: test-vector support

export interface ParsedJws {
  compact: string;
  headerBytes: Uint8Array;
  payloadBytes: Uint8Array;
  signature: Uint8Array;
  header: JsonObject;
  alg: JwsAlg;
  /** Exact bytes `header.payload` as transmitted (RFC 7515 §5.1). */
  signingInput: Uint8Array;
}

/** A key the verifier holds, with the algorithm it is configured for (asor-02 §6 step 1). */
export type TrustedKey =
  | { alg: "EdDSA" | "Ed25519"; publicKey: KeyObject }
  // test-vector support: the asor-02 vectors are signed with a shared HS256 secret.
  | { alg: "HS256"; secret: Uint8Array };

const SECTION = "RFC 7515 §7.1";

/**
 * Strict compact-JWS parse: exactly three base64url segments in canonical
 * form, a JSON object header with a string `alg`. `alg: none` and algorithms
 * other than EdDSA / HS256 are refused here with codes `alg_none` and
 * `alg_unsupported`.
 */
export function parseJws(compact: string): Outcome<ParsedJws> {
  const parts = compact.split(".");
  if (parts.length !== 3) return fail("malformed", SECTION, "a compact JWS has exactly three segments");
  const [h, p, s] = parts as [string, string, string];
  const headerBytes = b64urlDecodeStrict(h);
  const payloadBytes = b64urlDecodeStrict(p);
  const signature = b64urlDecodeStrict(s);
  if (!headerBytes || !payloadBytes || !signature || h === "" || p === "") {
    return fail("malformed", SECTION, "segment is not canonical unpadded base64url");
  }
  const parsed = parseJson(headerBytes, "RFC 7515 §4");
  if (!parsed.ok) return parsed;
  const header = parsed.value;
  if (!isObject(header) || typeof header.alg !== "string") {
    return fail("malformed", "RFC 7515 §4.1.1", "protected header must be an object with a string alg");
  }
  if (header.alg === "none") return fail("alg_none", "RFC 8725 §3.2", 'alg "none" is never acceptable');
  if (header.alg !== "EdDSA" && header.alg !== "HS256") {
    return fail("alg_unsupported", "RFC 7515 §4.1.1", `unsupported alg ${JSON.stringify(header.alg)}`);
  }
  return {
    ok: true,
    value: {
      compact,
      headerBytes,
      payloadBytes,
      signature,
      header,
      alg: header.alg,
      signingInput: new Uint8Array(Buffer.from(`${h}.${p}`, "ascii")),
    },
  };
}

/** True iff the signature verifies under `key` and the header alg is the one configured for it. */
export function verifyJws(jws: ParsedJws, key: TrustedKey): boolean {
  if (jws.alg !== key.alg) return false;
  if (key.alg !== "HS256") {
    if (jws.signature.length !== 64) return false;
    try {
      return cryptoVerify(null, jws.signingInput, key.publicKey, jws.signature);
    } catch {
      return false;
    }
  }
  // test-vector support
  const mac = createHmac("sha256", key.secret).update(jws.signingInput).digest();
  return mac.length === jws.signature.length && timingSafeEqual(mac, jws.signature);
}
