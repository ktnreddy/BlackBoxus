// Copies the static files next to the compiled scripts, giving a folder
// the browser can load as an unpacked extension.
import { cpSync, readdirSync, rmSync } from "node:fs";

cpSync("static", "dist", { recursive: true });
// Tests are not part of the extension.
for (const file of readdirSync("dist")) {
  if (file.endsWith(".test.js")) rmSync(`dist/${file}`);
}
