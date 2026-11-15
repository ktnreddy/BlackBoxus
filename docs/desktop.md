# Desktop app

The desktop app lives in `apps/desktop`. It is built with
[Tauri 2](https://v2.tauri.app/): the screens are a small Svelte 5 page
(`src/`) shown in the system webview (WebView2 on Windows), and everything
else runs in Rust (`src-tauri/`) on top of `client-core`.

Windows is the first platform. macOS and Linux builds come later.

## How it is split

| Runs in | Does |
| --- | --- |
| The window (Svelte) | Shows screens, takes what the user types, shows what comes back |
| Rust (`src-tauri`) | Talks to the server, derives and holds keys, encrypts and decrypts, keeps the local copy |

## What is stored on the computer

| What | Where | Protected by |
| --- | --- | --- |
| Email address, account ID, server | `account.json` in the app's data folder | Nothing secret in it |
| Secret Key | Windows Credential Manager (`BlackBoxus` entry) | Windows encrypts it for the signed-in user |
| Master password | Nowhere | Typed each time you unlock |

The Secret Key alone cannot open anything: unlocking also needs the master
password. Other programs running as the same Windows user can read
Credential Manager entries, which is why the Secret Key is stored there and
the master password is not.

## Accounts

- **Create an account:** the master password must have at least 12
  characters and score at least 3 out of 4 with
  [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs), which also counts the
  email address against it. Key derivation uses the default Argon2id
  settings (128 MiB, 4 passes). The app then signs in to the new account
  and shows the Emergency Kit, which can be printed or saved as a PDF.
- **Sign in on this computer:** email address, Secret Key and master
  password. The Secret Key is then stored, so later only the master
  password is needed.
- **Unlock:** signs in with the stored Secret Key and the master password.
  It needs the internet for now; unlocking offline from the local copy
  comes with vault sync.

The window never holds keys and never talks to the network. A master
password is passed to Rust once, cleared from the page straight away and
wiped from Rust memory after use (`Zeroizing`). Decrypted secrets are only
sent to the window when the user asks to see one.

## Security settings

- **Content security policy** (`tauri.conf.json`): only the app's own
  scripts, styles and fonts load; no inline scripts or styles, no network
  access, no frames, no form posts. Fonts are bundled, so nothing is
  fetched from Google or any other site at run time.
- **Commands are allow-listed.** `build.rs` lists the commands the window
  may call and `capabilities/main.json` grants only those. None of Tauri's
  built-in plugins (files, shell, HTTP and so on) is enabled.
- **No global Tauri object** (`withGlobalTauri: false`) and a frozen
  JavaScript prototype (`freezePrototype: true`), which makes prototype
  pollution in the page harder to turn into IPC abuse.
- **One instance only.** A second launch focuses the open window instead
  of running a second copy against the same local data.
- **Drag and drop is off**, so files dropped on the window are ignored.
- Developer tools exist only in debug builds.

Server connections use rustls with Mozilla's root certificates, never
follow redirects and time out after 30 seconds. Answers larger than 4 MiB
are cut off, and every answer is checked by `client-core` before use.

Known limits, to address later:

- The installer is not code-signed, so SmartScreen warns on first run.
- Strings typed into the page live in the webview's memory until it frees
  them; the page can clear its own copy but cannot wipe the browser
  engine's.
- Tauri's isolation pattern (an extra check on every IPC message) is not
  enabled yet; it becomes worth it once the page has more dependencies.

## Developing

You need Rust (pinned in `rust-toolchain.toml`), Node.js 22 and, on
Windows, the WebView2 runtime (already part of Windows 10 and 11).

```sh
cd apps/desktop
npm ci
npm run tauri dev     # runs the app with live reload
npm run check         # type-checks the screens
npx tauri build       # builds the Windows installer (.exe) in target/release/bundle/nsis
```

Debug builds can talk to a local server (see `docs/deployment.md`) instead
of the real one; release builds ignore this setting:

```sh
BLACKBOXUS_API_URL=http://127.0.0.1:8787 npm run tauri dev
BLACKBOXUS_API_URL=http://127.0.0.1:8787 cargo test -p blackboxus-desktop -- --ignored
```

On Linux and macOS, debug builds keep the Secret Key in memory only, so it
is gone when the app closes.

On Linux, building also needs the WebKitGTK development libraries:
`libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev`.

## Installer

Every push to `main` that touches the app or the crates it uses runs the
**Desktop** workflow, which builds the Windows installer and attaches it to
the run's page for 14 days. The installer installs for the current user
only and fetches the WebView2 runtime if a computer lacks it.
