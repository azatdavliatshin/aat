import { walkChain, type VerifyOptions, type WalkSuccess } from "./chain.js";
import { asor02, type Asor02Token } from "./profiles/asor02.js";
import { aat01, type Aat01Token } from "./profiles/aat01.js";
import { verifyAat02, type Aat02Presentation, type Aat02Token } from "./profiles/aat02.js";
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
export { verifyAat02, AAT02_DEFAULTS, type Aat02Presentation, type Aat02Token, type TrustAnchor } from "./profiles/aat02.js";

/**
 * Verify a root-first chain of compact JWS tokens. Failures are returned,
 * never thrown. HS256 is accepted only when the caller lists it in
 * `acceptedAlgs` and supplies an HS256 key (test-vector support).
 * For "aat-02", `tokens` may also be a §7.4 presentation `{aat_chain, aat_pop}`.
 */
export function verifyChain(
  tokens: readonly string[] | Aat02Presentation,
  profile: Profile,
  options: VerifyOptions,
): WalkSuccess<Asor02Token | Aat01Token | Aat02Token> | Failure {
  if (profile === "aat-02") return verifyAat02(tokens, options);
  if (!Array.isArray(tokens)) throw new Error(`profile ${profile} takes a token array`);
  if (profile === "asor-02") return walkChain(tokens, asor02, options);
  if (profile === "aat-01") return walkChain(tokens, aat01, options);
  throw new Error(`profile ${profile} is not implemented`);
}
