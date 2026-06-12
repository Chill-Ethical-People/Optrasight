import { BATCH_ONE_ALLOWED_PATHS } from "./release";
import type { AccessMode } from "../../../shared/accessPolicy";

const DEFAULT_BATCH_ONE_REDIRECT = "#/osint";
const ROOT_PATH = "/";
const HASH_PREFIX = "#";
const BATCH_ONE_REVIEW_PATHS = new Set<string>([ROOT_PATH, "/osint", "/intel", "/threat-actors"]);

export function stripHashQuery(path: string): string {
  const qix = path.indexOf("?");
  const routePath = qix >= 0 ? path.slice(0, qix) : path;
  return routePath || ROOT_PATH;
}

export function hashPath(hash: string): string {
  const rawPath = hash.startsWith(HASH_PREFIX) ? hash.slice(1) : hash;
  return stripHashQuery(rawPath || ROOT_PATH);
}

export function batchOneRedirectFor(hash: string, accessMode?: AccessMode | null): string | null {
  const path = hashPath(hash || `${HASH_PREFIX}${ROOT_PATH}`);
  if (accessMode === "guest" && !BATCH_ONE_REVIEW_PATHS.has(path)) return DEFAULT_BATCH_ONE_REDIRECT;
  if (!BATCH_ONE_ALLOWED_PATHS.has(path)) return DEFAULT_BATCH_ONE_REDIRECT;
  return null;
}
