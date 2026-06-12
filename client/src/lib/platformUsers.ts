export type PlatformUserRole = "admin" | "threat_intel_expert" | "detection_engineer" | "reviewer";
export type PlatformUserStatus = "active" | "disabled";

export interface PlatformUser {
  id: string;
  email: string;
  role: PlatformUserRole;
  tenantId: string;
  displayName?: string | null;
  status?: PlatformUserStatus;
  passwordMustChange?: boolean | number | null;
  mfaEnabled?: boolean | number | null;
  mfaVerifiedAt?: string | null;
  lastLoginAt?: string | null;
}

export interface PlatformUserForm {
  email: string;
  password: string;
  role: PlatformUserRole;
  displayName: string;
  status: PlatformUserStatus;
}

export const PLATFORM_ROLE_LABELS: Record<PlatformUserRole, string> = {
  admin: "Platform administrator",
  threat_intel_expert: "Threat analyst",
  detection_engineer: "Detection engineer",
  reviewer: "Read-only reviewer",
};

export function emptyPlatformUserForm(): PlatformUserForm {
  return {
    email: "",
    password: "",
    role: "threat_intel_expert",
    displayName: "",
    status: "active",
  };
}

export function formFromPlatformUser(user: PlatformUser): PlatformUserForm {
  return {
    email: user.email,
    password: "",
    role: user.role,
    displayName: user.displayName ?? "",
    status: user.status ?? "active",
  };
}

export function isComplexPassword(value: string) {
  return value.length >= 12
    && /[a-z]/.test(value)
    && /[A-Z]/.test(value)
    && /\d/.test(value)
    && /[^A-Za-z0-9]/.test(value);
}

export function platformUserErrorMessage(err: unknown) {
  const raw = String((err as any)?.message ?? err ?? "");
  try {
    const jsonText = raw.replace(/^\d+:\s*/, "");
    const parsed = JSON.parse(jsonText);
    return parsed.detail || parsed.message || raw;
  } catch {
    return raw;
  }
}
