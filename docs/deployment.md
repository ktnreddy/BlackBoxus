# Deployment

The BlackBoxus server runs on Cloudflare Workers with a D1 database, on the Free plan. It is deployed automatically by GitHub Actions after every push to `main` that passes all checks. The API is described in [spec section 12](spec/12-server-api.md).

## One-time setup

1. Create a Cloudflare account and choose the `workers.dev` subdomain (`blackboxus`).
2. Create an account API token from the **Edit Cloudflare Workers** template, with **D1: Write** added.
3. In the GitHub repository, add two Actions secrets: `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

Everything else happens on the first deploy:

- the D1 database `blackboxus` is created and its schema applied (`crates/server-worker/migrations`);
- the Worker `api` is deployed to `https://api.blackboxus.workers.dev`;
- the server's secrets are generated in the workflow and stored in Cloudflare, and the key transparency log's public key is printed in the workflow summary. Clients must have that public key built in.

## Every deploy

The `Deploy server` job in `.github/workflows/ci.yml`:

1. runs only after formatting, lints, tests and the dependency audit pass;
2. applies any new database migrations;
3. builds the Worker with `worker-build` (WebAssembly with SIMD) and deploys it;
4. checks that the server answers.

Server secrets are never replaced. If only some of them exist, the job stops and asks for a manual fix.

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
