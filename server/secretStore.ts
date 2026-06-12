import Database from "better-sqlite3";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const SECRET_DB_PATH = process.env.OPTRASIGHT_SECRET_DB
  ? resolve(process.env.OPTRASIGHT_SECRET_DB)
  : join(resolve(process.cwd(), "data"), "secrets", "optrasight-secrets.db");

try {
  mkdirSync(dirname(SECRET_DB_PATH), { recursive: true, mode: 0o700 });
} catch {
  // Directory creation failure will surface when SQLite opens the file.
}

const secretSqlite = new Database(SECRET_DB_PATH);
secretSqlite.pragma("journal_mode = WAL");
try { chmodSync(SECRET_DB_PATH, 0o600); } catch { /* best-effort on non-POSIX hosts */ }

secretSqlite.exec(`
  CREATE TABLE IF NOT EXISTS secret_values (
    tenant_id TEXT NOT NULL,
    owner_type TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    secret_name TEXT NOT NULL,
    secret_value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, owner_type, owner_id, secret_name)
  );
`);

export const secretStore = {
  path: SECRET_DB_PATH,

  getSecret(tenantId: string, ownerType: string, ownerId: string, secretName: string): string | null {
    const row = secretSqlite.prepare(`
      SELECT secret_value AS secretValue
      FROM secret_values
      WHERE tenant_id = ? AND owner_type = ? AND owner_id = ? AND secret_name = ?
    `).get(tenantId, ownerType, ownerId, secretName) as { secretValue?: string } | undefined;
    return row?.secretValue ?? null;
  },

  setSecret(tenantId: string, ownerType: string, ownerId: string, secretName: string, secretValue: string): void {
    secretSqlite.prepare(`
      INSERT INTO secret_values (tenant_id, owner_type, owner_id, secret_name, secret_value, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(tenant_id, owner_type, owner_id, secret_name)
      DO UPDATE SET secret_value = excluded.secret_value, updated_at = excluded.updated_at
    `).run(tenantId, ownerType, ownerId, secretName, secretValue, new Date().toISOString());
  },

  deleteSecret(tenantId: string, ownerType: string, ownerId: string, secretName: string): void {
    secretSqlite.prepare(`
      DELETE FROM secret_values
      WHERE tenant_id = ? AND owner_type = ? AND owner_id = ? AND secret_name = ?
    `).run(tenantId, ownerType, ownerId, secretName);
  },

  deleteOwnerSecrets(tenantId: string, ownerType: string, ownerId: string): void {
    secretSqlite.prepare(`
      DELETE FROM secret_values
      WHERE tenant_id = ? AND owner_type = ? AND owner_id = ?
    `).run(tenantId, ownerType, ownerId);
  },
};
