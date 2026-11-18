import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Tauri serves the built files itself; Vite only runs a server during
// development. See https://v2.tauri.app/start/frontend/vite/
//
// `tauri android dev` on a real phone sets TAURI_DEV_HOST to this
// computer's address so the phone can reach the server; otherwise it
// stays on this computer only.
declare const process: { env: Record<string, string | undefined> };
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || "127.0.0.1",
    ...(host ? { hmr: { protocol: "ws", host, port: 1421 } } : {}),
    watch: { ignored: ["**/src-tauri/**"] },
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    // WebView2 on Windows and Android's WebView are Chromium based and kept
    // up to date.
    target: "chrome120",
    sourcemap: false,
    // Fonts are small; keep them as files so the CSP can stay strict.
    assetsInlineLimit: 0,
  },
});
