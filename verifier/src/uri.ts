/**
 * RFC 3986 `absolute-URI`, transcribed from the collected ABNF (Appendix A).
 * One pattern per rule, named after it, so each line can be checked against
 * the RFC. ASCII only; the input is matched as given (no normalisation, no
 * case folding, no trimming). Quoted ABNF literals are case-insensitive
 * (RFC 5234 §2.3), so `"v"` in IPvFuture matches `v` and `V`.
 */

// ALPHA, DIGIT, HEXDIG (RFC 5234 Appendix B.1)
const ALPHA = "[A-Za-z]";
const DIGIT = "[0-9]";
const HEXDIG = "[0-9A-Fa-f]";

// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
const unreserved = "[A-Za-z0-9\\-._~]";
// sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
const subDelims = "[!$&'()*+,;=]";
// pct-encoded   = "%" HEXDIG HEXDIG
const pctEncoded = `%${HEXDIG}${HEXDIG}`;

// pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
const pchar = `(?:${unreserved}|${pctEncoded}|${subDelims}|[:@])`;
// segment       = *pchar
const segment = `${pchar}*`;
// segment-nz    = 1*pchar
const segmentNz = `${pchar}+`;

// path-abempty  = *( "/" segment )
const pathAbempty = `(?:/${segment})*`;
// path-absolute = "/" [ segment-nz *( "/" segment ) ]
const pathAbsolute = `/(?:${segmentNz}(?:/${segment})*)?`;
// path-rootless = segment-nz *( "/" segment )
const pathRootless = `${segmentNz}(?:/${segment})*`;
// path-empty    = 0<pchar>
const pathEmpty = "";

// query         = *( pchar / "/" / "?" )
const query = `(?:${pchar}|[/?])*`;

// scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
const scheme = `${ALPHA}(?:${ALPHA}|${DIGIT}|[+\\-.])*`;

// dec-octet     = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
const decOctet = `(?:${DIGIT}|[1-9]${DIGIT}|1${DIGIT}{2}|2[0-4]${DIGIT}|25[0-5])`;
// IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
const IPv4address = `${decOctet}\\.${decOctet}\\.${decOctet}\\.${decOctet}`;

// h16           = 1*4HEXDIG
const h16 = `${HEXDIG}{1,4}`;
// ls32          = ( h16 ":" h16 ) / IPv4address
const ls32 = `(?:${h16}:${h16}|${IPv4address})`;
/** `[ *n( h16 ":" ) h16 ]`, the part before "::" in the last seven IPv6address forms. */
const before = (n: number): string => `(?:(?:${h16}:){0,${n}}${h16})?`;
// IPv6address, its nine alternatives in the RFC's order
const IPv6address = `(?:${[
  `(?:${h16}:){6}${ls32}`, //                            6( h16 ":" ) ls32
  `::(?:${h16}:){5}${ls32}`, //                     "::" 5( h16 ":" ) ls32
  `(?:${h16})?::(?:${h16}:){4}${ls32}`, // [               h16 ] "::" 4( h16 ":" ) ls32
  `${before(1)}::(?:${h16}:){3}${ls32}`, // [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
  `${before(2)}::(?:${h16}:){2}${ls32}`, // [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
  `${before(3)}::${h16}:${ls32}`, //        [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
  `${before(4)}::${ls32}`, //               [ *4( h16 ":" ) h16 ] "::"              ls32
  `${before(5)}::${h16}`, //                [ *5( h16 ":" ) h16 ] "::"              h16
  `${before(6)}::`, //                      [ *6( h16 ":" ) h16 ] "::"
].join("|")})`;
// IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
const IPvFuture = `[vV]${HEXDIG}+\\.(?:${unreserved}|${subDelims}|:)+`;
// IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
const IPliteral = `\\[(?:${IPv6address}|${IPvFuture})\\]`;
// reg-name      = *( unreserved / pct-encoded / sub-delims )
const regName = `(?:${unreserved}|${pctEncoded}|${subDelims})*`;
// host          = IP-literal / IPv4address / reg-name
const host = `(?:${IPliteral}|${IPv4address}|${regName})`;
// port          = *DIGIT
const port = `${DIGIT}*`;
// userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
const userinfo = `(?:${unreserved}|${pctEncoded}|${subDelims}|:)*`;
// authority     = [ userinfo "@" ] host [ ":" port ]
const authority = `(?:${userinfo}@)?${host}(?::${port})?`;

// hier-part     = "//" authority path-abempty / path-absolute / path-rootless / path-empty
const hierPart = `(?://${authority}${pathAbempty}|${pathAbsolute}|${pathRootless}|${pathEmpty})`;
// absolute-URI  = scheme ":" hier-part [ "?" query ]
const absoluteUri = new RegExp(`^${scheme}:${hierPart}(?:\\?${query})?$`);

/** RFC 3986 §4.3 `absolute-URI`: a URI with no fragment. */
export function isAbsoluteUri(s: string): boolean {
  return absoluteUri.test(s);
}
