/**
 * Verification failures are values, never exceptions. `code` is the outcome
 * name (asor-02 §6.2, Table 2 for that profile), `section` the draft section
 * of the rule that failed, `check` the named check inside the profile.
 */
export interface Failure {
  ok: false;
  code: string;
  section: string;
  message: string;
  /** Position of the offending token in the chain, where one applies. */
  token?: number;
  check?: string;
}

export function fail(
  code: string,
  section: string,
  message: string,
  extra: { token?: number; check?: string } = {},
): Failure {
  return { ok: false, code, section, message, ...extra };
}

export type Outcome<T> = { ok: true; value: T } | Failure;
