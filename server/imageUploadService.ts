import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import sharp from "sharp";

export type StoredImage = {
  bytes: number;
  mimeType: "image/png" | "image/jpeg";
  objectKey: string;
  publicUrl: string;
};

export interface ImageObjectStore {
  deletePublicUrl(publicUrl: string | null | undefined): Promise<void>;
  put(data: Buffer, extension: "png" | "jpg"): Promise<{ objectKey: string; publicUrl: string }>;
  readPublicUrl(publicUrl: string | null | undefined): Promise<Buffer | undefined>;
}

export class UploadValidationError extends Error {
  constructor(
    message: string,
    readonly statusCode: 400 | 413 = 400,
  ) {
    super(message);
    this.name = "UploadValidationError";
  }
}

/** Filesystem implementation with opaque, server-generated object keys only. */
export class LocalImageObjectStore implements ImageObjectStore {
  constructor(
    private readonly rootDirectory: string,
    private readonly publicPrefix: string,
  ) {}

  async put(data: Buffer, extension: "png" | "jpg") {
    await mkdir(this.rootDirectory, { recursive: true, mode: 0o750 });
    const objectKey = `${randomUUID()}.${extension}`;
    await writeFile(join(this.rootDirectory, objectKey), data, { flag: "wx", mode: 0o640 });
    return { objectKey, publicUrl: `${this.publicPrefix}/${objectKey}` };
  }

  async readPublicUrl(publicUrl: string | null | undefined): Promise<Buffer | undefined> {
    const objectKey = this.objectKeyFromPublicUrl(publicUrl);
    if (!objectKey) return undefined;
    try {
      return await readFile(join(this.rootDirectory, objectKey));
    } catch {
      return undefined;
    }
  }

  async deletePublicUrl(publicUrl: string | null | undefined): Promise<void> {
    const objectKey = this.objectKeyFromPublicUrl(publicUrl);
    if (!objectKey) return;
    await rm(join(this.rootDirectory, objectKey), { force: true });
  }

  private objectKeyFromPublicUrl(publicUrl: string | null | undefined): string | null {
    if (!publicUrl) return null;
    let pathname: string;
    try {
      pathname = new URL(publicUrl, "http://optrasight.invalid").pathname;
    } catch {
      return null;
    }
    if (!pathname.startsWith(`${this.publicPrefix}/`)) return null;
    const objectKey = basename(pathname);
    return /^[0-9a-f-]{36}\.(?:png|jpg)$/i.test(objectKey) ? objectKey : null;
  }
}

type ClientLogoInput = {
  contentBase64: string;
  fileName: string;
};

export class ClientLogoUploadService {
  static readonly maxInputBytes = 2 * 1024 * 1024;
  static readonly maxPixels = 16_000_000;

  constructor(private readonly objectStore: ImageObjectStore) {}

  async store(input: ClientLogoInput): Promise<StoredImage> {
    const expectedFormat = this.extensionFromFileName(input.fileName);
    const source = this.decodeBase64(input.contentBase64);
    if (source.byteLength === 0) throw new UploadValidationError("empty logo file");
    if (source.byteLength > ClientLogoUploadService.maxInputBytes) {
      throw new UploadValidationError("logo is larger than 2MB", 413);
    }

    let metadata: sharp.Metadata;
    try {
      metadata = await sharp(source, {
        animated: false,
        failOn: "warning",
        limitInputPixels: ClientLogoUploadService.maxPixels,
      }).metadata();
    } catch {
      throw new UploadValidationError("logo is not a valid PNG or JPEG image");
    }
    if (metadata.format !== expectedFormat) {
      throw new UploadValidationError("file content does not match its PNG or JPEG extension");
    }
    if (!metadata.width || !metadata.height || (metadata.pages && metadata.pages > 1)) {
      throw new UploadValidationError("logo must be a single-frame image with valid dimensions");
    }

    const pipeline = sharp(source, {
      animated: false,
      failOn: "warning",
      limitInputPixels: ClientLogoUploadService.maxPixels,
    }).rotate();
    const normalized =
      expectedFormat === "png"
        ? await pipeline.png({ compressionLevel: 9 }).toBuffer()
        : await pipeline.jpeg({ quality: 88, mozjpeg: true }).toBuffer();
    if (normalized.byteLength > ClientLogoUploadService.maxInputBytes) {
      throw new UploadValidationError("normalized logo is larger than 2MB", 413);
    }

    const extension = expectedFormat === "png" ? "png" : "jpg";
    const stored = await this.objectStore.put(normalized, extension);
    return {
      ...stored,
      bytes: normalized.byteLength,
      mimeType: expectedFormat === "png" ? "image/png" : "image/jpeg",
    };
  }

  read(publicUrl: string | null | undefined): Promise<Buffer | undefined> {
    return this.objectStore.readPublicUrl(publicUrl);
  }

  delete(publicUrl: string | null | undefined): Promise<void> {
    return this.objectStore.deletePublicUrl(publicUrl);
  }

  private extensionFromFileName(fileName: string): "png" | "jpeg" {
    const extension = fileName.toLowerCase().match(/\.(png|jpe?g)$/)?.[1];
    if (extension === "png") return "png";
    if (extension === "jpg" || extension === "jpeg") return "jpeg";
    throw new UploadValidationError("use a PNG or JPEG logo");
  }

  private decodeBase64(value: string): Buffer {
    if (!value || value.length > Math.ceil(ClientLogoUploadService.maxInputBytes / 3) * 4 + 4) {
      throw new UploadValidationError("invalid base64 image", value ? 413 : 400);
    }
    if (value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw new UploadValidationError("invalid base64 image");
    }
    return Buffer.from(value, "base64");
  }
}
