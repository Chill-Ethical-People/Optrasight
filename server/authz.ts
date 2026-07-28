import type { NextFunction, Request, Response } from "express";
import type { User } from "@shared/schema";
import {
  hasCapability,
  isBatchOneApiAllowed,
  resolveCapabilities,
  type AccessMode,
  type Capability,
} from "@shared/accessPolicy";
import { storage } from "./storage";

export const BATCH_ONE_RELEASE = process.env.OPTRASIGHT_BATCH_ONE_RELEASE !== "0";

export interface AuthedRequest extends Request {
  user?: User & { accessMode?: AccessMode; capabilities?: Capability[] };
  accessMode?: AccessMode;
  capabilities?: Capability[];
  effectiveTenantId?: string;
}

export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.header("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return res.status(401).json({ detail: "missing bearer token" });

  const u = storage.getUser(m[1]);
  if (!u) return res.status(401).json({ detail: "invalid token" });

  req.accessMode = u.accessMode ?? "credentialed";
  req.capabilities = resolveCapabilities({
    role: u.role,
    accessMode: req.accessMode,
    batchOne: BATCH_ONE_RELEASE,
  });
  req.user = { ...u, capabilities: req.capabilities };

  if (BATCH_ONE_RELEASE && !isBatchOneApiAllowed({
    method: req.method,
    path: req.path,
    accessMode: req.accessMode,
  })) {
    return res.status(403).json({
      detail: req.accessMode === "guest"
        ? "Review access is read-only except approved analysis tasking."
        : "This workflow is outside the Batch One release scope.",
    });
  }

  req.effectiveTenantId = u.tenantId;

  next();
}

export function authPayload(u: User & { accessToken: string; accessMode: AccessMode }) {
  const capabilities = resolveCapabilities({
    role: u.role,
    accessMode: u.accessMode,
    batchOne: BATCH_ONE_RELEASE,
  });
  return {
    access_token: u.accessToken,
    token_type: "bearer",
    tenant_id: u.tenantId,
    role: u.role,
    email: u.email,
    access_mode: u.accessMode,
    capabilities,
  };
}

export function requireCapability(
  req: AuthedRequest,
  res: Response,
  capability: Capability,
  detail = "required capability missing",
): boolean {
  if (!hasCapability(req.capabilities, capability)) {
    res.status(403).json({ detail });
    return false;
  }
  return true;
}
