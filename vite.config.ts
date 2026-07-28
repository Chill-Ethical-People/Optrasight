import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets"),
    },
  },
  root: path.resolve(import.meta.dirname, "client"),
  // Local verification can reuse the existing public asset library instead of
  // recopying ~200 MB of portraits through an iCloud-backed workspace.
  publicDir: process.env.OPTRASIGHT_SKIP_PUBLIC_COPY === "1"
    ? false
    : path.resolve(import.meta.dirname, "client", "public"),
  base: "./",
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
    rollupOptions: {
      // Keep module reads bounded on APFS/iCloud-backed workspaces. Rollup's
      // high default concurrency can otherwise stall while opening hundreds
      // of dependency files at once.
      maxParallelFileOps: Number(process.env.OPTRASIGHT_BUILD_FILE_OPS || 32),
    },
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"],
    },
  },
});
