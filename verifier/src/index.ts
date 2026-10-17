import type { Profile, VerifyResult } from "./types.js";

export type * from "./types.js";
export { b64urlDecode, b64urlEncode } from "./encoding.js";

export function verifyChain(_tokens: readonly string[], _profile: Profile): VerifyResult {
  throw new Error("not implemented");
}
