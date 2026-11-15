import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Component styles go into the CSS file, never into inline <style> tags,
    // so the content security policy needs no 'unsafe-inline'.
    css: "external",
  },
};
