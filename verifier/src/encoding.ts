/** base64url without padding (RFC 7515 Appendix C). */
export function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function b64urlDecode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error("invalid base64url");
  }
  return new Uint8Array(Buffer.from(text, "base64url"));
}

/**
 * Strict decoder: alphabet only, no padding, and the canonical encoding of the
 * bytes it yields (non-zero trailing bits are rejected). `undefined` on any
 * deviation.
 */
export function b64urlDecodeStrict(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return undefined;
  const bytes = new Uint8Array(Buffer.from(text, "base64url"));
  return b64urlEncode(bytes) === text ? bytes : undefined;
}
