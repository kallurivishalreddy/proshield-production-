import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// The REAL ProShield backend runs via `python -m scripts.proxy_server`
// (analyst plane) on 127.0.0.1:8088. In dev we proxy /api and /health to
// it so the app talks to the actual SecureProxy wire boundary.
const BACKEND = process.env.PROSHIELD_BACKEND_URL || "http://127.0.0.1:8088";

// https://vite.dev/config/
export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss(), viteSingleFile()],
  resolve: {
    alias: [
      {
        // The installed lucide-react tarball is missing its ESM entry
        // (dist/esm/lucide-react.mjs), which breaks Vite's "module"
        // resolution. The CJS bundle IS intact — alias to it directly.
        find: "lucide-react",
        replacement: path.resolve(
          __dirname,
          "node_modules/lucide-react/dist/cjs/lucide-react.js"
        ),
      },
      {
        find: "@",
        replacement: path.resolve(__dirname, "src"),
      },
    ],
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: BACKEND, changeOrigin: true },
      "/health": { target: BACKEND, changeOrigin: true },
    },
  },
  build: {
    // Build output lands in frontend/soc — served by the backend's
    // StaticFiles mount at /static/soc/, same-origin with /api/proxy.
    outDir: path.resolve(__dirname, "../soc"),
    emptyOutDir: true,
  },
});
