// Checks the built site: every page has the shared header and footer,
// every internal link and asset exists, and nothing is loaded from another
// site or run as a script.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import assert from "node:assert/strict";

const pages = readdirSync("dist").filter((f) => f.endsWith(".html"));
assert.ok(pages.length >= 5, "pages are missing");
for (const page of pages) {
  const html = readFileSync(`dist/${page}`, "utf8");
  assert.ok(!html.includes("<!-- header -->") && !html.includes("<!-- footer -->"), `${page}: partial not filled in`);
  assert.ok(!/<script/i.test(html), `${page}: has a script`);
  assert.ok(!/\son[a-z]+=/i.test(html), `${page}: has an inline event handler`);
  assert.ok(!/style=/i.test(html), `${page}: has an inline style, which the policy blocks`);
  assert.match(html, /<title>[^<]+<\/title>/, `${page}: no title`);
  assert.match(html, /<html lang="en">/, `${page}: no language`);
  for (const [, url] of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
    if (/^https?:\/\//.test(url)) {
      assert.fail(`${page}: loads or links to another site: ${url}`);
    }
    if (url.startsWith("#")) continue;
    const [path, hash] = url.split("#");
    const file = path === "/" ? "index.html" : path.replace(/^\//, "");
    const target = existsSync(`dist/${file}`) ? file : `${file}.html`;
    assert.ok(existsSync(`dist/${target}`), `${page}: broken link ${url}`);
    if (hash) {
      assert.ok(readFileSync(`dist/${target}`, "utf8").includes(`id="${hash}"`), `${page}: missing anchor ${url}`);
    }
  }
}
for (const font of readdirSync("dist/fonts").filter((f) => f.endsWith(".woff2"))) {
  assert.ok(readFileSync("dist/styles.css", "utf8").includes(font), `${font} is not used`);
}
console.log(`ok: ${pages.length} pages`);
