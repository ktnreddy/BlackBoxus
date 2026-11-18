// Builds the static site into dist/: fills in the shared header and footer,
// and copies the fonts from their packages so nothing is fetched from
// another site at run time.
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";

const partials = {
  header: readFileSync("partials/header.html", "utf8"),
  footer: readFileSync("partials/footer.html", "utf8"),
};

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/fonts", { recursive: true });

for (const file of readdirSync("src")) {
  if (file.endsWith(".html")) {
    const page = file.replace(/\.html$/, "");
    let html = readFileSync(`src/${file}`, "utf8")
      .replace("<!-- header -->", partials.header)
      .replace("<!-- footer -->", partials.footer);
    // Mark the current page in the navigation.
    html = html.replace(`href="/${page === "index" ? "" : page}" data-nav`, (m) => `${m} aria-current="page"`);
    writeFileSync(`dist/${file}`, html);
  } else {
    cpSync(`src/${file}`, `dist/${file}`, { recursive: true });
  }
}

const fonts = [
  ["dm-sans", "dm-sans-latin-300-normal.woff2"],
  ["dm-sans", "dm-sans-latin-400-normal.woff2"],
  ["dm-sans", "dm-sans-latin-500-normal.woff2"],
  ["dm-sans", "dm-sans-latin-600-normal.woff2"],
  ["dm-mono", "dm-mono-latin-400-normal.woff2"],
];
for (const [family, file] of fonts) {
  cpSync(`node_modules/@fontsource/${family}/files/${file}`, `dist/fonts/${file}`);
}
// The fonts' licence (SIL Open Font License) travels with them.
cpSync("node_modules/@fontsource/dm-sans/LICENSE", "dist/fonts/LICENSE-dm-sans.txt");
cpSync("node_modules/@fontsource/dm-mono/LICENSE", "dist/fonts/LICENSE-dm-mono.txt");
