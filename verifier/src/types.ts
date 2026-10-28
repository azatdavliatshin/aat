/**
 * Claim shapes of the two profiles under study. Section references are to
 * draft-niyikiza-oauth-attenuating-agent-tokens-01 ("AAT-01") and
 * draft-asor-wimse-agent-delegation-chain-02 ("asor-02"). The aat-02 profile
 * (draft -02) keeps its own token shape in profiles/aat02.ts.
 */

export type Profile = "aat-01" | "aat-02" | "asor-02";

/** RFC 7519 NumericDate. */
export type NumericDate = number;

/** JWK public key (RFC 7800 `jwk` member). */
export interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  [member: string]: unknown;
}

// ---------------------------------------------------------------- AAT-01

/** AAT-01 §3.4: argument constraint, discriminated by `constraint_type`. */
export type AatConstraint =
  | { constraint_type: "exact"; value: string | number | boolean }
  | {
      constraint_type: "range";
      min?: number;
      max?: number;
      min_inclusive?: boolean;
      max_inclusive?: boolean;
    }
  | { constraint_type: "one_of"; values: unknown[] }
  | { constraint_type: "not_one_of"; excluded: unknown[] }
  | { constraint_type: "contains"; required: unknown[] }
  | { constraint_type: "subset"; allowed: unknown[] }
  | { constraint_type: "wildcard" }
  | { constraint_type: "all"; constraints: AatConstraint[] }
  | { constraint_type: "any"; constraints: AatConstraint[] };

/** AAT-01 §3.3: the single `attenuating_agent_token` authorization detail. */
export interface AatAuthorizationDetail {
  type: "attenuating_agent_token";
  /** tool name -> argument name -> constraint; `{}` means no argument restriction. */
  tools: Record<string, Record<string, AatConstraint>>;
}

/** AAT-01 §3.2, Table 1. */
export interface AatClaims {
  /** §3.2: unique token identifier. */
  jti: string;
  /** §3.2: root issuer URI (root) or JWK Thumbprint URI of the signing key (derived). */
  iss: string;
  /** §3.2 */
  iat: NumericDate;
  /** §3.2; §4.4 (I3). */
  exp: NumericDate;
  /** §3.2, RFC 7800: holder public key. */
  cnf: { jwk: Jwk };
  /** §3.2; §4.3 (I2): 0 in the root. */
  del_depth: number;
  /** §3.2; §4.3 (I2). */
  del_max_depth: number;
  /** §3.2; §4.6 (I5): absent in the root, required in derived tokens. */
  par_hash?: string;
  /** §3.2, §3.3; §4.5 (I4). */
  authorization_details: Array<AatAuthorizationDetail | { type: string; [member: string]: unknown }>;
}

/** AAT-01 §5.2: proof-of-possession JWT presented with the leaf (I6). Claims per Table of §5.2. */
export interface AatPopClaims {
  [claim: string]: unknown;
}

// --------------------------------------------------------------- asor-02

/** asor-02 §4.2: constraint object, closed: `key` plus exactly one typed member. */
export type AsorConstraint =
  | { key: string; max: number }
  | { key: string; max_lifetime: number }
  | { key: string; max_subtree: number }
  | { key: string; min: number }
  | { key: string; one_of: unknown[] }
  | { key: string; not_one_of: unknown[] }
  | { key: string; prefix: string }
  | { key: string; rank: string; order: string[] };

/** asor-02 §4: the single `agent_delegation` authorization detail (RFC 9396). */
export interface AsorAuthorizationDetail {
  type: "agent_delegation";
  /** §4, §4.1: literal, wildcard (`a.*`) or opaque scope strings. */
  scopes: string[];
  /** §4.2 */
  constraints: AsorConstraint[];
}

/** asor-02 §3. */
export interface AsorClaims {
  /** §3: RFC 9068 claims. */
  iss: string;
  exp: NumericDate;
  iat: NumericDate;
  jti: string;
  /** §3: string or non-empty array of strings; checked on the leaf (§6 step 8). */
  aud: string | string[];
  /** §3, §3.1: the Principal, identical at every hop. */
  sub: string;
  /** §3, §3.1: the Acting Agent at this hop. */
  client_id: string;
  /** §3: exactly one `agent_delegation` detail (§4). */
  authorization_details: AsorAuthorizationDetail[];
  /** §3, §7: RFC 7800 confirmation (presence and shape checked in -02 reference code). */
  cnf: { jwk?: Jwk; jkt?: string; [member: string]: unknown };
  /** §3: 0 in DT_0. */
  del_depth: number;
  /** §3: required in DT_0; MUST NOT be increased by a child (§4.3). */
  del_max_depth?: number;
  /** §3, §5: absent in DT_0, required otherwise. */
  par_hash?: string;
}

/** JOSE protected header shared by both profiles (asor-02 §3; AAT-01 §3). */
export interface JoseHeader {
  alg: string;
  typ?: string;
  kid?: string;
  /** asor-02 §3: informational label only. */
  c14n?: "JCS";
}

/** Verification outcome; asor-02 §6.2 names the outcomes, AAT-01 §7 the checks. */
export type VerifyResult = { ok: true } | { ok: false; reason: string };
