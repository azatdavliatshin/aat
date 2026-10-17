import { createHash, createPublicKey } from "node:crypto";
import { b64urlEncode } from "./encoding.js";
import { sha256b64u } from "./hash.js";
import { isObject, parseJson, type JsonObject } from "./json.js";
import { parseJws, verifyJws } from "./jws.js";

/**
 * asor-02 §6 step 6 / §7: holder binding by a DPoP proof (RFC 9449) against
 * the leaf's `cnf`. EdDSA proofs with an OKP/Ed25519 `jwk` only; `x5t#S256`
 * confirmation (mTLS) is not implemented. Returns a message on failure.
 */

export interface DpopInput {
  proof: string;
  method: string;
  url: string;
  /** The leaf Delegation Token as presented, for the `ath` binding (RFC 9449 §4.2). */
  accessToken: string;
  now: number;
  /** Accepted distance of `iat` from `now`, seconds. */
  skew?: number;
}

/** RFC 7638 thumbprint of an Ed25519 public JWK. */
export function okpThumbprint(jwk: JsonObject): string {
  const json = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(jwk.kty)},"x":${JSON.stringify(jwk.x)}}`;
  return b64urlEncode(createHash("sha256").update(json).digest());
}

/** RFC 9449 §4.3: compare htu without query and fragment. */
function stripQuery(u: string): string {
  return u.split("#")[0]!.split("?")[0]!;
}

export function verifyHolderBinding(cnf: JsonObject, d: DpopInput): string | undefined {
  const jws = parseJws(d.proof);
  if (!jws.ok) return `proof: ${jws.message}`;
  const { header, alg } = jws.value;
  if (alg !== "EdDSA") return "proof must be signed with EdDSA";
  if (header.typ !== "dpop+jwt") return 'proof typ must be "dpop+jwt"';
  const jwk = header.jwk;
  if (!isObject(jwk) || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || "d" in jwk) {
    return "proof header jwk must be a public Ed25519 key";
  }
  let publicKey;
  try {
    publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  } catch {
    return "proof header jwk is not a valid key";
  }
  if (!verifyJws(jws.value, { alg: "EdDSA", publicKey })) return "proof signature does not verify";

  const claims = parseJson(jws.value.payloadBytes, "RFC 9449 §4.2");
  if (!claims.ok || !isObject(claims.value)) return "proof payload is not a JSON object";
  const c = claims.value;
  if (typeof c.jti !== "string" || c.jti === "") return "proof jti missing"; // replay cache is the caller's
  if (c.htm !== d.method) return "proof htm does not match the request method";
  if (typeof c.htu !== "string" || stripQuery(c.htu) !== stripQuery(d.url)) return "proof htu does not match the request URI";
  if (typeof c.iat !== "number" || Math.abs(c.iat - d.now) > (d.skew ?? 60)) return "proof iat outside the accepted window";
  if (c.ath !== sha256b64u(new Uint8Array(Buffer.from(d.accessToken, "ascii")))) return "proof ath does not bind the presented token";

  // RFC 7800 / RFC 9449 §6: cnf names the key by thumbprint (jkt) or carries it (jwk).
  const thumb = okpThumbprint(jwk);
  if (typeof cnf.jkt === "string") return cnf.jkt === thumb ? undefined : "proof key does not match cnf.jkt";
  if (isObject(cnf.jwk)) return okpThumbprint(cnf.jwk) === thumb ? undefined : "proof key does not match cnf.jwk";
  return "cnf carries no jkt or jwk this verifier can check";
}
