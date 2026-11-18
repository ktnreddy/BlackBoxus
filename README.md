# BlackBoxus

A zero-knowledge, end-to-end encrypted password manager, designed to stay secure even if its own server is compromised.

> [!WARNING]
> **BlackBoxus is in early development and has not been independently audited.**
> Do not store real passwords in it yet. This notice will be removed only after an external security audit.

## Why BlackBoxus

Most password managers advertise "zero-knowledge encryption," yet research published in 2026 showed that several leading products could leak passwords to a malicious server through flaws in the protocol around the encryption. BlackBoxus is built around that threat model from day one:

- **Malicious-server security.** Every response from the server is verified on your device. The server cannot read, modify, roll back or silently drop your data, and cannot weaken the encryption settings.
- **Two-secret key derivation.** Your vault key comes from your master password *and* a random 128-bit Secret Key that never leaves your devices. A stolen server database cannot be cracked offline, however weak a password is.
- **Everything is encrypted.** Item names, URLs, folders and notes are encrypted, not just passwords.
- **Post-quantum ready.** Sharing uses a hybrid of classical and post-quantum cryptography (X25519 + ML-KEM-768), so data recorded today stays safe from future quantum computers.
- **Passkey-native.** Store passkeys, and unlock your vault with a passkey (WebAuthn PRF).
- **Clickjacking-resistant autofill.** The autofill picker never lives inside the web page.

## Cryptography at a glance

| Purpose | Algorithm |
| --- | --- |
| Password stretching | Argon2id |
| Login (server never sees the password) | OPAQUE (RFC 9807) |
| Encryption of vault data | XChaCha20-Poly1305 |
| Key derivation | HKDF-SHA-256 |
| Sharing between users | X-Wing (X25519 + ML-KEM-768), signed by the sender |
| Signatures | Ed25519 + ML-DSA-65 |

All cryptography lives in one Rust library, `vault-core`, shared by every app. The full design is in [`docs/architecture.md`](docs/architecture.md), and the protocol specification is being written in [`docs/spec/`](docs/spec/).

## Tech stack

| Part | Technology | Runs on |
| --- | --- | --- |
| Crypto core | Rust (`vault-core`) | Every client |
| Server | Rust on Cloudflare Workers, D1, Durable Objects | Cloudflare |
| Website | Static site | Cloudflare Pages |
| Desktop app | Tauri 2 + Svelte 5 + TypeScript | Windows, Linux and macOS |
| Browser extension | TypeScript + WebAssembly | Firefox, Chrome |
| Android app | The desktop app, built for phones by Tauri 2 | Android 9 and later |
| iPhone and iPad app | The desktop app, built for iOS by Tauri 2 | iOS 16 and later (in testing, not signed yet) |

## Repository layout

```
apps/
  desktop/       The app for Windows, macOS, Linux, Android and iOS: Svelte screens
                 in src/, Rust in src-tauri/, the Android project in
                 src-tauri/gen/android/
  extension/     The browser extension for Chrome, Edge, Brave and Firefox
  website/       The website, plain HTML and CSS on Cloudflare Pages
crates/
  vault-core/    All cryptography and the vault data model
  client-core/   Client flows shared by every app (sign-up, login, key lookups)
  wire/          JSON messages of the server API, shared by server and clients
  server-core/   Platform-independent server logic
  server-worker/ The server on Cloudflare Workers and D1
fuzz/            Fuzz targets for every parser of untrusted data
docs/
  android.md
  apple.md
  architecture.md
  deployment.md
  desktop.md
  releasing.md   How a release is built, checked and published
  releases/      Notes for each release
  spec/          Protocol specification
```

## Building

Requires the Rust toolchain pinned in `rust-toolchain.toml` (installed automatically by `rustup`).

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

The desktop app also needs Node.js 22; see [`docs/desktop.md`](docs/desktop.md). For the Android app, see [`docs/android.md`](docs/android.md); for the Mac and iPhone apps, [`docs/apple.md`](docs/apple.md).

Fuzz testing uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz
cargo fuzz list
cargo fuzz run -s none tampering -- -max_total_time=60
```

## Roadmap

1. Protocol specification and threat model
2. `vault-core`: key derivation, item encryption, login, sharing
3. Server on Cloudflare (running at `https://api.blackboxus.workers.dev`; see [docs/deployment.md](docs/deployment.md))
4. Desktop app and browser extension
5. Android app
6. Mac and iPhone apps (written; signing and iPhone autofill to come)

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not open public issues for security problems.

## License

BlackBoxus is free software licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
