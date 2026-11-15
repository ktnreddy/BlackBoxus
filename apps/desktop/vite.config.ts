import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Tauri serves the built files itself; Vite only runs a server during
// development. See https://v2.tauri.app/start/frontend/vite/
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    watch: { ignored: ["**/src-tauri/**"] },
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    // WebView2 on Windows is Chromium based and kept up to date.
    target: "chrome120",
    sourcemap: false,
    // Fonts are small; keep them as files so the CSP can stay strict.
    assetsInlineLimit: 0,
  },
});
