import express from 'express';
import type { Express } from 'express';
import rateLimit from "express-rate-limit";
import fs from "node:fs";
import path from "node:path";

function staticRateLimit(opts: { windowMs: number; max: number }) {
  return rateLimit({
    windowMs: opts.windowMs,
    limit: opts.max,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: "too many requests",
  });
}

export function serveStatic(app: Express) {
  const distPath = path.resolve(__dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`,
    );
  }

  app.use(staticRateLimit({ windowMs: 60_000, max: 600 }), express.static(distPath));

  // fall through to index.html if the file doesn't exist
  app.use("/{*path}", staticRateLimit({ windowMs: 60_000, max: 600 }), (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
