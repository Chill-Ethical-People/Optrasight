import nodemailer from "nodemailer";
import type { SmtpSettingsDTO } from "@shared/schema";
import { secretStore } from "./secretStore";

const OWNER_TYPE = "email_delivery";
const OWNER_ID = "smtp";
const CONFIG_SECRET = "config";
const PASSWORD_SECRET = "password";
const COOLDOWN_SECRET = "cooldown_until";

type StoredSmtpConfig = Omit<SmtpSettingsDTO, "hasPassword" | "configured">;

const DEFAULT_CONFIG: StoredSmtpConfig = {
  enabled: false,
  host: "",
  port: 587,
  secure: false,
  username: "",
  fromName: "OptraSight Threat Intelligence",
  fromAddress: "",
  replyTo: "",
};

function readConfig(tenantId: string): StoredSmtpConfig {
  const raw = secretStore.getSecret(tenantId, OWNER_TYPE, OWNER_ID, CONFIG_SECRET);
  if (!raw) return { ...DEFAULT_CONFIG };
  try {
    const parsed = JSON.parse(raw) as Partial<StoredSmtpConfig>;
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      port: Number(parsed.port || DEFAULT_CONFIG.port),
      enabled: parsed.enabled === true,
      secure: parsed.secure === true,
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export function getSmtpSettings(tenantId: string): SmtpSettingsDTO {
  const config = readConfig(tenantId);
  const hasPassword = !!secretStore.getSecret(tenantId, OWNER_TYPE, OWNER_ID, PASSWORD_SECRET);
  return {
    ...config,
    hasPassword,
    configured: !!config.host && !!config.fromAddress && (!config.username || hasPassword),
  };
}

export function saveSmtpSettings(
  tenantId: string,
  input: Omit<StoredSmtpConfig, "replyTo"> & {
    replyTo?: string;
    password?: string;
    clearPassword?: boolean;
  },
): SmtpSettingsDTO {
  const config: StoredSmtpConfig = {
    enabled: input.enabled,
    host: input.host,
    port: input.port,
    secure: input.secure,
    username: input.username,
    fromName: input.fromName,
    fromAddress: input.fromAddress,
    replyTo: input.replyTo || "",
  };
  secretStore.setSecret(tenantId, OWNER_TYPE, OWNER_ID, CONFIG_SECRET, JSON.stringify(config));
  if (input.clearPassword) secretStore.deleteSecret(tenantId, OWNER_TYPE, OWNER_ID, PASSWORD_SECRET);
  if (input.password) secretStore.setSecret(tenantId, OWNER_TYPE, OWNER_ID, PASSWORD_SECRET, input.password);
  secretStore.deleteSecret(tenantId, OWNER_TYPE, OWNER_ID, COOLDOWN_SECRET);
  return getSmtpSettings(tenantId);
}

export function getSmtpCooldownSeconds(tenantId: string): number {
  const raw = secretStore.getSecret(tenantId, OWNER_TYPE, OWNER_ID, COOLDOWN_SECRET);
  const until = Number(raw || 0);
  if (!Number.isFinite(until) || until <= Date.now()) {
    if (raw) secretStore.deleteSecret(tenantId, OWNER_TYPE, OWNER_ID, COOLDOWN_SECRET);
    return 0;
  }
  return Math.max(1, Math.ceil((until - Date.now()) / 1000));
}

export function setSmtpCooldown(tenantId: string, seconds: number): void {
  secretStore.setSecret(
    tenantId,
    OWNER_TYPE,
    OWNER_ID,
    COOLDOWN_SECRET,
    String(Date.now() + Math.max(1, seconds) * 1000),
  );
}

export function clearSmtpCooldown(tenantId: string): void {
  secretStore.deleteSecret(tenantId, OWNER_TYPE, OWNER_ID, COOLDOWN_SECRET);
}

function createSmtpTransport(tenantId: string) {
  const config = readConfig(tenantId);
  const password = secretStore.getSecret(tenantId, OWNER_TYPE, OWNER_ID, PASSWORD_SECRET);
  if (!config.enabled) throw new Error("email delivery is disabled");
  if (!config.host || !config.fromAddress) throw new Error("SMTP sender settings are incomplete");
  if (config.username && !password) throw new Error("SMTP password is not configured");
  const senderDomain = config.fromAddress.split("@")[1]?.trim().toLowerCase();

  return {
    config,
    transporter: nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      requireTLS: !config.secure,
      name: senderDomain || undefined,
      auth: config.username ? { user: config.username, pass: password || "" } : undefined,
      authMethod: config.username ? "LOGIN" : undefined,
      tls: {
        servername: config.host,
        minVersion: "TLSv1.2",
      },
      connectionTimeout: 15_000,
      greetingTimeout: 15_000,
      socketTimeout: 60_000,
    }),
  };
}

export function describeSmtpError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/421\b|temporar(?:y|ily)|deferr/i.test(message)) {
    return "The SMTP provider temporarily deferred the message. Your saved settings authenticated, but the provider asked the platform to retry later. Wait a few minutes and try again; repeated failures may require the mail administrator to review sending limits.";
  }
  if (/connection timeout|timed? ?out|etimedout/i.test(message)) {
    return "The SMTP connection succeeded, but the provider did not complete message submission before the timeout. The approved draft is unchanged. Retry later; if this continues, ask the mail administrator to review SMTP submission restrictions.";
  }
  if (/535\b|auth(?:entication)? failed|invalid login/i.test(message)) {
    return "SMTP authentication failed. Check the username and use the provider's SMTP or app password, then test the saved connection again.";
  }
  if (/certificate|self[- ]signed|tls|ssl/i.test(message)) {
    return "The SMTP TLS connection failed. Confirm the host, port, and implicit TLS setting (usually on for port 465 and off for STARTTLS on port 587).";
  }
  if (/timed? ?out|econnrefused|enotfound|getaddrinfo|connection/i.test(message)) {
    return "The platform could not reach the SMTP server. Confirm the host and port and check whether the server allows outbound SMTP connections.";
  }
  return `SMTP operation failed: ${message}`;
}

export function classifySmtpFailure(error: unknown): {
  code: "smtp_temporarily_deferred" | "smtp_submission_timeout" | "smtp_delivery_failed";
  retryable: boolean;
  retryAfterSeconds?: number;
} {
  const message = error instanceof Error ? error.message : String(error);
  if (/421\b|temporar(?:y|ily)|deferr/i.test(message)) {
    return { code: "smtp_temporarily_deferred", retryable: true, retryAfterSeconds: 900 };
  }
  if (/connection timeout|timed? ?out|etimedout|econnreset/i.test(message)) {
    return { code: "smtp_submission_timeout", retryable: true, retryAfterSeconds: 300 };
  }
  return { code: "smtp_delivery_failed", retryable: false };
}

export async function verifySmtpConnection(tenantId: string) {
  const { transporter } = createSmtpTransport(tenantId);
  try {
    await transporter.verify();
    return { verified: true as const };
  } finally {
    transporter.close();
  }
}

export async function sendSmtpEmail(
  tenantId: string,
  message: {
    recipients: string[];
    subject: string;
    text: string;
    html: string;
    logo?: { data: Buffer; mimeType: "image/png" | "image/jpeg" };
  },
) {
  const { config, transporter } = createSmtpTransport(tenantId);
  if (!message.recipients.length) throw new Error("the client profile has no notification recipients");
  try {
    return await transporter.sendMail({
      from: { name: config.fromName, address: config.fromAddress },
      to: message.recipients,
      envelope: {
        from: config.fromAddress,
        to: message.recipients,
      },
      replyTo: config.replyTo || undefined,
      subject: message.subject,
      text: message.text,
      html: message.html,
      attachments: message.logo
        ? [
            {
              filename: `client-logo.${message.logo.mimeType === "image/png" ? "png" : "jpg"}`,
              content: message.logo.data,
              contentType: message.logo.mimeType,
              cid: "client-logo",
              contentDisposition: "inline",
            },
          ]
        : undefined,
    });
  } finally {
    transporter.close();
  }
}
