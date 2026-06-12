/**
 * Production-mode gate.
 *
 * When OPTRASIGHT_STRICT=1 (or NODE_ENV=production AND OPTRASIGHT_STRICT is
 * unset — defaults to strict in prod), every code path that would silently
 * fall back to deterministic mock output must instead throw or refuse to run.
 *
 * Mock paths still exist for the local demo / first-boot seeding but are
 * gated through this single helper so the policy is auditable in one place.
 *
 * Locked product constraint (carried across the OptraSight build):
 *   "DeepSeek live + productional, no mock fallback — surface real errors."
 */

const TRUTHY = new Set(["1", "true", "yes", "on"]);
const FALSY = new Set(["0", "false", "no", "off"]);

function readEnvFlag(name: string): boolean | undefined {
  const v = process.env[name];
  if (!v) return undefined;
  const k = v.trim().toLowerCase();
  if (TRUTHY.has(k)) return true;
  if (FALSY.has(k)) return false;
  return undefined;
}

/**
 * `true` when the server refuses to silently fall back to deterministic
 * mock output. Defaults to `true` in production (NODE_ENV=production),
 * `false` otherwise. Either default can be overridden with OPTRASIGHT_STRICT.
 *
 * Demo mode disables strict regardless of NODE_ENV — see `isDemoMode()`.
 */
export function isStrictProduction(): boolean {
  if (isDemoMode()) return false;
  const explicit = readEnvFlag("OPTRASIGHT_STRICT");
  if (explicit !== undefined) return explicit;
  return process.env.NODE_ENV === "production";
}

/**
 * `true` when the server is running as the public pitch / sales-demo build.
 *
 * Demo mode keeps mock-adapter output enabled and tags all freshly-seeded
 * findings with `evidence_source='demo'` so the UI can label them honestly.
 * It is mutually exclusive with explicit `OPTRASIGHT_STRICT=1` — `assertModeConsistency()`
 * throws at boot if both are set.
 */
export function isDemoMode(): boolean {
  return readEnvFlag("OPTRASIGHT_DEMO") === true;
}

/**
 * Boot-time sanity check. Throws if the operator set mutually exclusive flags
 * (OPTRASIGHT_STRICT=1 AND OPTRASIGHT_DEMO=1) so misconfigurations fail loud
 * instead of silently producing a half-strict / half-demo box.
 */
export function assertModeConsistency(): void {
  const explicitStrict = readEnvFlag("OPTRASIGHT_STRICT") === true;
  if (explicitStrict && isDemoMode()) {
    throw new Error(
      "OPTRASIGHT_STRICT=1 and OPTRASIGHT_DEMO=1 are mutually exclusive. " +
        "Demo mode is a sales-facing build that intentionally allows curated mock data; " +
        "strict mode forbids it. Pick one.",
    );
  }
}

/**
 * Throw if the caller is about to enter a mock fallback path while running
 * in strict production mode. The `label` is surfaced in the error so the
 * dashboard / logs identify exactly which subsystem refused.
 *
 * Routes should catch this and return 409 (no provider) or 502 (live error)
 * rather than 500.
 */
export class MockFallbackBlockedError extends Error {
  readonly subsystem: string;
  constructor(subsystem: string, hint: string) {
    super(
      `[${subsystem}] mock fallback is blocked in strict production mode. ${hint} ` +
        `Set OPTRASIGHT_STRICT=0 to re-enable mock paths (not recommended in production).`,
    );
    this.name = "MockFallbackBlockedError";
    this.subsystem = subsystem;
  }
}

export function blockMockOrThrow(subsystem: string, hint: string): void {
  if (isStrictProduction()) {
    throw new MockFallbackBlockedError(subsystem, hint);
  }
}

/** Logs a one-line banner on boot summarising the current mode. */
export function logProductionMode(): void {
  const env = process.env.NODE_ENV ?? "development";
  let banner: string;
  if (isDemoMode()) {
    banner = `[optrasight] DEMO mode — curated demo data enabled, real outbound calls restricted (NODE_ENV=${env}).`;
  } else if (isStrictProduction()) {
    banner = `[optrasight] STRICT production mode — mock fallbacks DISABLED (NODE_ENV=${env}).`;
  } else {
    banner = `[optrasight] permissive mode — mock fallbacks ENABLED (NODE_ENV=${env}). Set OPTRASIGHT_STRICT=1 to disable.`;
  }
  console.log(banner);
}
