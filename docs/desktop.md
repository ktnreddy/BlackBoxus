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
| Vault copies | `vaults/*.vault` in the app's data folder | Sealed with the account's key set |
| Last key transparency tree head | `vaults/tree-head.json` | Public; used to catch a log that goes back in time |

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

## Vaults

After unlocking, the app syncs every vault the account can read: it
downloads new log entries, looks up any new authors through key
transparency, replays and verifies the whole signed log, then fetches the
vault keys and items. A new account gets its first vault, "Personal", on
its first sync. A sealed copy of each vault is saved after every sync and
loaded on the next one, so a server that rolls a vault back or forks it is
caught.

- **Items:** logins, secure notes and cards can be added, edited and
  deleted. Item lists and views never carry concealed values (passwords,
  card numbers, security codes); the window asks for one only when the
  eye is clicked, and hides it again after 30 seconds.
- **Copying** happens in Rust, so concealed values never pass through the
  window. On Windows the copy is kept out of clipboard history and cloud
  clipboard sync, and it is cleared after 30 seconds, or on locking, if
  it is still on the clipboard.
- **Auto-lock:** after 10 minutes without keyboard or mouse input.
- **Password generator:** random passwords (8 to 64 characters, letters
  that look alike left out) or passphrases of 3 to 10 words from the
  [EFF Large Wordlist](https://www.eff.org/dice) (by the Electronic
  Frontier Foundation, CC BY 3.0 US), all from the operating system's
  random number generator without bias. It opens from the sidebar, or
  from a password field to fill it in.

## Sharing

Vaults are shared by **sharing ID**: the account ID written as 26
characters, such as `0QKX4Q-SX48Q-J7J8K-HZYQ2-D7Y27`. Each person finds
theirs on the Share screen. Email addresses are not used, so the server
never has to say whether an address has an account.

1. The owner enters the other person's sharing ID and looks them up. The
   app fetches both accounts' keys through key transparency and verifies
   them.
2. Both see the same 60-digit safety number (on the other side, under
   Compare). The owner can share only after ticking that it matches.
3. The app records the new member in the vault's signed log and sends them
   the vault key, encrypted to their keys and signed.
4. On the recipient's next sync, the app checks the sender's signature
   with keys from key transparency, stores the vault key for this account
   and syncs the vault. Shares that fail any check are ignored.

Owners can add people as "Can edit" or "Can view". Changing roles and
removing people come later.

The key transparency log's public key is built into the app from
`src-tauri/log-key.txt`. It is printed in the Deploy job's summary after
the server's first deploy; until it is filled in, vaults cannot be synced.

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
export BLACKBOXUS_API_URL=http://127.0.0.1:8787
export BLACKBOXUS_LOG_KEY=<the local server's log key, from generate_secrets>
npm run tauri dev
cargo test -p blackboxus-desktop -- --ignored
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
