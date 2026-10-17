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
