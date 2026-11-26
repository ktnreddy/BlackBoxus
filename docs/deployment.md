# Deployment

The BlackBoxus server runs on Cloudflare Workers with a D1 database, on the Free plan. It is deployed automatically by GitHub Actions after every push to `main` that passes all checks. The API is described in [spec section 12](spec/12-server-api.md).

## One-time setup

1. Create a Cloudflare account and choose the `workers.dev` subdomain (`blackboxus`).
2. Create an account API token from the **Edit Cloudflare Workers** template, with **D1: Write** and **Cloudflare Pages: Edit** added (Pages is for the website; an existing token can be edited to add it).
3. In the GitHub repository, add two Actions secrets: `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

Everything else happens on the first deploy:

- the D1 database `blackboxus-apac` is created in Asia-Pacific, near most people using BlackBoxus, and its schema applied (`crates/server-worker/migrations`);
- the Worker `api` is deployed to `https://api.blackboxus.workers.dev`;
- the server's secrets are generated in the workflow and stored in Cloudflare, and the key transparency log's public key is printed in the workflow summary. Clients must have that public key built in.

## Every deploy

The `Deploy server` job in `.github/workflows/ci.yml`:

1. runs only after formatting, lints, tests and the dependency audit pass;
2. applies any new database migrations;
3. builds the Worker with `worker-build` (WebAssembly with SIMD) and deploys it;
4. checks that the server answers.

Server secrets are never replaced. If only some of them exist, the job stops and asks for a manual fix.

## Website

The website in `apps/website` is plain HTML and CSS with no scripts. `npm test` builds it into `dist/` (filling in the shared header and footer and copying the fonts from their packages) and checks every page: no scripts, no inline styles, no links or loads from other sites, and no broken links.

The **Website** workflow (`.github/workflows/website.yml`) runs after every push to `main` that touches `apps/website`. It creates the Cloudflare Pages project `blackboxus` on its first run and publishes the site to `https://blackboxus.pages.dev`. Response headers, including a content security policy that allows only the site's own styles, fonts and images, are in `apps/website/src/_headers`.

To look at it locally:

```sh
cd apps/website
npm ci
npm test
python3 -m http.server -d dist 8080
```

## Running locally

```sh
cd crates/server-worker
npm ci
cargo install --locked worker-build@0.9.0
rustup target add wasm32-unknown-unknown
cargo run -p server-worker --example generate_secrets -- /tmp/secrets.json
# Copy the three values into crates/server-worker/.dev.vars as NAME=value lines.
npx wrangler d1 migrations apply blackboxus --local
npx wrangler dev --local
```

`.dev.vars` is ignored by Git; never commit real secrets.

## Limits to watch

- **CPU:** 10 ms per request on the Free plan. The costliest operations take about 1.5–2 ms.
- **Requests:** 100,000 per day.
- **D1:** 500 MB per database, 5 million rows read and 100,000 rows written per day, and 50 queries per request. Most requests write one rate limit row.
- **Key log:** about 23,000 accounts before the tree no longer fits in one row (spec section 12.11).
