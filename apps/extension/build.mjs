// Copies the static files next to the compiled scripts, giving a folder
// Chrome, Edge and Brave can load as an unpacked extension (dist/), and a
// copy with a Firefox manifest (dist-firefox/).
import { cpSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";

/** The add-on ID Firefox knows the extension by. The desktop app's
 *  `FIREFOX_IDS` must list it. */
const GECKO_ID = "{7ee1ca63-9148-4233-a256-ff54b5fbbdc9}";

cpSync("static", "dist", { recursive: true });
// Tests are not part of the extension.
for (const file of readdirSync("dist")) {
  if (file.endsWith(".test.js")) rmSync(`dist/${file}`);
}

// Firefox runs the background script as an event page rather than a
// service worker, identifies the add-on by a declared ID instead of a key,
// and ignores Chrome's version field.
rmSync("dist-firefox", { recursive: true, force: true });
cpSync("dist", "dist-firefox", { recursive: true });
const manifest = JSON.parse(readFileSync("static/manifest.json", "utf8"));
delete manifest.key;
delete manifest.minimum_chrome_version;
manifest.background = { scripts: ["background.js"], type: "module" };
manifest.browser_specific_settings = {
  gecko: { id: GECKO_ID, strict_min_version: "128.0" },
};
writeFileSync("dist-firefox/manifest.json", JSON.stringify(manifest, null, 2) + "\n");
