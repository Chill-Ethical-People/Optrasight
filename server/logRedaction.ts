const SENSITIVE_KEY_PATTERN = /password|token|secret|api[-_]?key|authorization|access_token|otpauth/i;
const LARGE_CONTENT_KEY_PATTERN = /body|content|payload|result|report|narrative|html|markdown|base64|data/i;

function redactSensitiveString(value: string): string {
  if (/^otpauth:\/\//i.test(value)) return "[redacted]";

  const redacted = value.replace(
    /([?&](?:secret|token|access_token|api[-_]?key)=)[^&#\s]+/gi,
    "$1[redacted]",
  );
  return redacted.length > 240 ? `${redacted.slice(0, 240)}…[truncated]` : redacted;
}

/**
 * Removes credentials, MFA enrollment material, and large response bodies before
 * API responses are written to the operational log.
 */
export function redactForLog(value: unknown, depth = 0): unknown {
  if (depth > 4) return "[truncated]";
  if (value == null) return value;
  if (typeof value === "string") return redactSensitiveString(value);
  if (Array.isArray(value)) return value.slice(0, 20).map((entry) => redactForLog(entry, depth + 1));
  if (typeof value !== "object") return value;

  const out: Record<string, unknown> = {};
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEY_PATTERN.test(key) || LARGE_CONTENT_KEY_PATTERN.test(key)) {
      out[key] = "[redacted]";
    } else {
      out[key] = redactForLog(raw, depth + 1);
    }
  }
  return out;
}
