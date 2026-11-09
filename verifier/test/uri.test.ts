import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyChain } from "../src/index.js";
import { mintRoot, newHolder } from "../src/testing/aat-mint.js";
import { isAbsoluteUri } from "../src/uri.js";

/** RFC 3986 Appendix A `absolute-URI`; each case: [input, reason]. */
const ACCEPTED: readonly (readonly [string, string])[] = [
  ["https://auth.example.com", "authority, path-abempty empty"],
  ["https://auth.example.com/", "path-abempty with one empty segment"],
  ["https://u:p@h.example:8443/a/b?c=d", "userinfo, port, path, query"],
  ["urn:ietf:params:oauth:jwk-thumbprint:sha-256:abc", "path-rootless; pchar includes ':'"],
  ["mailto:a@b.example", "path-rootless; pchar includes '@'"],
  ["http://[2001:db8::1]/", "IPv6address, compressed"],
  ["http://[::ffff:192.0.2.1]", "IPv6address with ls32 as IPv4address"],
  ["http://[v7.x]", "IPvFuture"],
  ["http://[V7.x]", "IPvFuture: the quoted \"v\" is case-insensitive (RFC 5234 §2.3)"],
  ["http://192.0.2.1", "IPv4address"],
  ["http://256.1.1.1", "not IPv4address (dec-octet), but a valid reg-name"],
  ["http://01.1.1.1", "not IPv4address (leading zero), but a valid reg-name"],
  ["a:", "hier-part is path-empty"],
  ["x:%41", "pct-encoded"],
  ["x:%4a", "HEXDIG is case-insensitive"],
  ["tag:example.com,2026:x", "sub-delims ',' in path-rootless"],
  ["s+v-1.x:/p", "scheme with '+', '-', '.', DIGIT; path-absolute"],
  ["x:?", "empty path, empty query"],
  ["x://", "empty authority (reg-name may be empty)"],
  ["x://h:", "empty port"],
  ["x://h?a/b?c", "query may contain '/' and '?'"],
  ["x:////a", "empty authority, then path-abempty \"//a\""],
  ["x:!$&'()*+,;=", "every sub-delim in a segment"],
  ["http://[1:2:3:4:5:6:7:8]", "IPv6 form 1: 6( h16 \":\" ) ls32"],
  ["http://[::2:3:4:5:6:7:8]", "IPv6 form 2: \"::\" 5( h16 \":\" ) ls32"],
  ["http://[1::3:4:5:6:7:8]", "IPv6 form 3"],
  ["http://[1:2::4:5:6:7:8]", "IPv6 form 4"],
  ["http://[1:2:3::5:6:7:8]", "IPv6 form 5"],
  ["http://[1:2:3:4::6:7:8]", "IPv6 form 6"],
  ["http://[1:2:3:4:5::7:8]", "IPv6 form 7"],
  ["http://[1:2:3:4:5:6::8]", "IPv6 form 8"],
  ["http://[1:2:3:4:5:6:7::]", "IPv6 form 9"],
  ["http://[::]", "IPv6 form 9 with no prefix"],
  ["http://[::1.2.3.4]", "IPv6 form 7, ls32 as IPv4address"],
  ["http://[::255.255.255.255]", "dec-octet upper bound"],
];

const REJECTED: readonly (readonly [string, string])[] = [
  ["https://a.example/#x", "fragment: not part of absolute-URI"],
  ["urn:x#y", "fragment"],
  ["not a uri", "space, and no ':' after a scheme"],
  ["https://a b", "space"],
  ["https://a.example/<x>", "'<' and '>' are outside the URI character set"],
  ["urn:x:%zz", "'%' not followed by two HEXDIG"],
  ["urn:x:%4", "'%' followed by one HEXDIG"],
  ["1http://a", "scheme must start with ALPHA"],
  [":x", "empty scheme"],
  ["", "empty string"],
  ["https", "no ':'"],
  ["http://[2001:db8::1", "unclosed IP-literal"],
  ["http://[1:2:3:4:5:6:7:8:9]", "nine h16 groups"],
  ["http://[g::1]", "'g' is not HEXDIG"],
  ["https://a.example/é", "non-ASCII"],
  ["http://a:b@c:d", "port must be DIGITs"],
  ["http://[::256.1.1.1]", "ls32: 256 is not a dec-octet"],
  ["http://[::01.1.1.1]", "ls32: 01 is not a dec-octet"],
  ["http://[1:2:3:4:5:6:7]", "seven h16 groups without '::'"],
  ["http://[1::2::3]", "two '::'"],
  ["http://[12345::1]", "h16 is at most four HEXDIG"],
  ["http://[v.x]", "IPvFuture needs 1*HEXDIG"],
  ["http://[v7.]", "IPvFuture needs a non-empty tail"],
  ["x:a\"b", "'\"' is outside the URI character set"],
  ["x:{}", "'{' and '}'"],
  ["x:a|b", "'|'"],
  ["x:a\\b", "'\\'"],
  ["x:a^b", "'^'"],
  ["x:a`b", "'`'"],
  ["x:a[b]", "'[' and ']' are only allowed in IP-literal"],
  [" https://a.example", "leading space (no trimming)"],
  ["https://a.example\n", "trailing newline"],
  ["https://a@b@c", "'@' may not appear in host"],
];

test("RFC 3986 absolute-URI: accepted", () => {
  for (const [s, why] of ACCEPTED) assert.equal(isAbsoluteUri(s), true, `${JSON.stringify(s)}: ${why}`);
});

test("RFC 3986 absolute-URI: rejected", () => {
  for (const [s, why] of REJECTED) assert.equal(isAbsoluteUri(s), false, `${JSON.stringify(s)}: ${why}`);
});

/** -02 §8 step 3k through the aat-02 profile, with a freshly minted root that names `iss` as its anchor's issuer. */
function verifyRootWithIss(iss: string) {
  const anchor = newHolder();
  const now = 1_800_000_000;
  const root = mintRoot({ anchor, iss, iat: now, exp: now + 3600, tools: { read_file: {} }, header: { alg: "Ed25519", typ: "aat+jwt" } });
  return verifyChain([root.compact], "aat-02", { anchors: [{ iss, jwk: anchor.jwk }], now });
}

test("aat-02 step 3k: root iss with a fragment is denied", () => {
  const r = verifyRootWithIss("https://auth.example.com/#x");
  assert.equal(r.ok, false);
  assert.ok(!r.ok && r.step === "3k" && r.code === "root_invalid", JSON.stringify(r));
});

test("aat-02 step 3k: an https issuer still permits", () => {
  const r = verifyRootWithIss("https://auth.example.com");
  assert.equal(r.ok, true, JSON.stringify(r));
});

test("aat-02 step 3k: root iss with malformed percent-encoding is denied", () => {
  const r = verifyRootWithIss("urn:x:%zz");
  assert.equal(r.ok, false);
  assert.ok(!r.ok && r.step === "3k" && r.code === "root_invalid", JSON.stringify(r));
});
