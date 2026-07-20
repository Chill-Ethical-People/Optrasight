import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import { afterEach, describe, expect, it } from "vitest";
import { ClientLogoUploadService, LocalImageObjectStore, UploadValidationError } from "../server/imageUploadService";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("client logo upload service", () => {
  it("normalizes valid images and stores them under an opaque server key", async () => {
    const directory = await mkdtemp(join(tmpdir(), "optrasight-logo-test-"));
    temporaryDirectories.push(directory);
    const service = new ClientLogoUploadService(new LocalImageObjectStore(directory, "/client-email-logos"));
    const source = await sharp({
      create: { width: 24, height: 24, channels: 4, background: "#4F46E5" },
    })
      .png()
      .toBuffer();

    const stored = await service.store({
      fileName: "customer-controlled-name.png",
      contentBase64: source.toString("base64"),
    });

    expect(stored.objectKey).toMatch(/^[0-9a-f-]{36}\.png$/);
    expect(stored.objectKey).not.toContain("customer-controlled-name");
    expect(await service.read(stored.publicUrl)).toBeInstanceOf(Buffer);

    await service.delete(stored.publicUrl);
    expect(await service.read(stored.publicUrl)).toBeUndefined();
  });

  it("rejects malformed data and extension-content mismatches", async () => {
    const directory = await mkdtemp(join(tmpdir(), "optrasight-logo-test-"));
    temporaryDirectories.push(directory);
    const service = new ClientLogoUploadService(new LocalImageObjectStore(directory, "/client-email-logos"));
    const png = await sharp({
      create: { width: 8, height: 8, channels: 3, background: "#22D3EE" },
    })
      .png()
      .toBuffer();

    await expect(service.store({ fileName: "logo.png", contentBase64: "not-base64" })).rejects.toBeInstanceOf(
      UploadValidationError,
    );
    await expect(service.store({ fileName: "logo.jpg", contentBase64: png.toString("base64") })).rejects.toThrow(
      "does not match",
    );
  });
});
