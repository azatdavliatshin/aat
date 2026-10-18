import { walkChain, type VerifyOptions, type WalkSuccess } from "./chain.js";
import { asor02, type Asor02Token } from "./profiles/asor02.js";
import { aat01, type Aat01Token } from "./profiles/aat01.js";
import type { Failure } from "./result.js";
import type { Profile } from "./types.js";

export type * from "./types.js";
export type { Failure } from "./result.js";
export type { Check, Node, Profile as ChainProfile, RequestContext, VerifyOptions, WalkSuccess } from "./chain.js";
export type { TrustedKey } from "./jws.js";
export { b64urlDecode, b64urlEncode } from "./encoding.js";
export { walkChain } from "./chain.js";
export { asor02 } from "./profiles/asor02.js";
export { aat01, type AatOptions } from "./profiles/aat01.js";

/**
 * Verify a root-first chain of compact JWS tokens. Failures are returned,
 * never thrown. HS256 is accepted only when the caller lists it in
 * `acceptedAlgs` and supplies an HS256 key (test-vector support).
 */
export function verifyChain(tokens: readonly string[], profile: Profile, options: VerifyOptions): WalkSuccess<Asor02Token | Aat01Token> | Failure {
  if (profile === "asor-02") return walkChain(tokens, asor02, options);
  if (profile === "aat-01") return walkChain(tokens, aat01, options);
  throw new Error(`profile ${profile} is not implemented`);
}
