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
| Offline unlock record | `offline-unlock.json` | The key set wrapped for the master password, as the server keeps it |
| Last key transparency tree head | `vaults/tree-head.json` | Public; used to catch a log that goes back in time |
| Paired browsers' keys | Windows Credential Manager (`browser-pairings` entry) | Windows encrypts it for the signed-in user |
| Browser host registration | `com.blackboxus.desktop.json` in the app's data folder, and a registry value per browser under `HKCU\Software\…\NativeMessagingHosts` | Nothing secret in it |

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
  Without a connection, it unlocks from the offline unlock record instead
  and shows the vaults from this computer's copies, read-only (spec
  section 6.8). When the connection is back, the app asks for the master
  password once more to sign in and sync.

## Vaults

After unlocking, the app syncs every vault the account can read: it
downloads new log entries, looks up any new authors through key
transparency, replays and verifies the whole signed log, then fetches the
vault keys and items. A new account gets its first vault, "Personal", on
its first sync. A sealed copy of each vault is saved after every sync and
loaded on the next one, so a server that rolls a vault back or forks it is
caught.

- **More vaults:** "New vault" makes another vault, to keep work and home
  apart or to share one set of items. Each vault's name is kept in an
  encrypted details item (spec section 6.3), so the server never sees it,
  and everyone the vault is shared with sees the same name. Anyone who can
  edit a vault's items can rename it. Vaults made before names existed
  show "Personal" or "Vault 2" until renamed.
- **Items:** logins, secure notes and cards can be added, edited and
  deleted. Item lists and views never carry concealed values (passwords,
  card numbers, security codes); the window asks for one only when the
  eye is clicked, and hides it again after 30 seconds.
- **One-time codes:** a login can hold a two-factor secret, pasted as the
  setup key or the `otpauth://totp/` link a site shows. The item shows the
  current code with a countdown, computed in Rust (RFC 6238; SHA-1,
  SHA-256 or SHA-512, 6 to 8 digits); the secret itself stays hidden.
  Counter-based (HOTP) secrets are refused, since a synced item can't
  safely hold a counter.
- **Copying** happens in Rust, so concealed values never pass through the
  window. On Windows the copy is kept out of clipboard history and cloud
  clipboard sync, and it is cleared after 30 seconds, or on locking, if
  it is still on the clipboard.
- **Watching for keys in your name:** once a day, after a sync, the app
  checks the key transparency log for every key recorded under the
  account's ID (spec section 9.5). If any is not this account's own, a red
  warning stays at the top of the window, checked again on every sync,
  because someone could be posing as the user to people who share with
  them. The time of the last check is kept in `vaults/self-check.json`.
- **Auto-lock:** after 10 minutes without keyboard or mouse input.
- **Password generator:** random passwords (8 to 64 characters, letters
  that look alike left out) or passphrases of 3 to 10 words from the
  [EFF Large Wordlist](https://www.eff.org/dice) (by the Electronic
  Frontier Foundation, CC BY 3.0 US), all from the operating system's
  random number generator without bias. It opens from the sidebar, or
  from a password field to fill it in.

## Settings

The settings dialog (sliders button at the bottom of the sidebar) holds:

- **Unlock with Windows Hello** (below).
- **Lock after** 1, 5, 10 (default), 15, 30 or 60 minutes without keyboard
  or mouse input. Saved in `settings.json`; nothing secret.
- **Master password:** asks for the current password and a new one (the
  same rules as a new account). The app signs in with the current password
  for a fresh session, registers the new one and wraps the same key set
  with it (spec section 3.9). The server ends every other session, so the
  app carries on with the fresh one and stores it for Windows Hello; the
  offline unlock record is replaced. Other devices must sign in again with
  the new password. The Secret Key, vaults and recovery key are unchanged.
- **Emergency Kit:** shows the Secret Key again for printing, after the
  master password is checked on this computer against the offline unlock
  record.
- **Sign out of this computer:** ends the session on the server (when
  online), deletes the Windows Hello key, and removes the Secret Key from
  the Credential Manager, the account record, the offline unlock record
  and every vault copy. Settings stay. The account and its vaults are not
  touched on the server.

## Recovery key

A recovery key lets someone who forgets their master password choose a
new one (spec section 11). It is optional, and made in Settings:

- The app asks for the master password and signs in again, because the
  server only accepts a new or removed recovery key from a session less
  than five minutes old. It then wraps the key set with the recovery key,
  sends the wrapped copy and a hash of the recovery token, and ends that
  extra session.
- The new key is shown once, in a new Emergency Kit to print or save. It is
  not stored on this computer.

"Forgot your master password?" on the unlock and sign-in screens starts a
recovery. The recovery key opens the key set, the user chooses a new
master password, and the server replaces the old login and ends every
session. If this computer already has the account, its Secret Key is
kept; otherwise a new one is made. The app then signs in, turns Windows
Hello unlock off (it held the old session), and makes a new recovery key at
once, because the old one has been typed here. The new Emergency Kit shows
both.

## Trusted contacts

"Trusted contacts" in the sidebar lets an account name one person who can
ask to see its vaults if something happens to the owner (spec sections
11.4 and 11.5).

- **Naming a contact:** their sharing ID is looked up through key
  transparency and both people compare the safety number, as for sharing.
  The owner picks a waiting period of 1, 3, 7, 14 or 30 days and enters the
  master password, since the server takes a grant only from a session less
  than five minutes old. The app signs the grant, encrypts a fresh
  emergency key to the contact's keys, wraps the key set with that key, and
  uploads both. The server can open neither.
- **A request:** the contact asks from the same screen. On every sync the
  owner's app shows a red bar with the date access opens and a Deny button,
  until the request is denied or the wait is over.
- **Opening:** after the wait the contact's app fetches the grant, checks
  the owner's signature against keys from key transparency, unwraps the key
  set and checks it is the one the owner published. The server also hands
  over a read-only session for the owner's account, valid for a day, so the
  app can sync their vaults with the usual checks. They open in a separate
  read-only window; passwords can be revealed and copied but nothing can be
  changed. Closing it ends the session and deletes the copies (kept under
  `vaults/emergency/` while open, and also deleted on locking).
- **Removing** the contact ends any access they were given. Anything they
  already saw may be in their own notes, so important passwords should be
  changed.

Email notification of a request needs a mail service, which BlackBoxus
does not have yet, so the owner learns of it the next time the app syncs.
Choosing a longer waiting period covers people who open the app rarely.

## Windows Hello

Settings → "Unlock with Windows Hello" lets the app unlock with a face,
fingerprint or PIN instead of the master password (spec section 10.4).

- Turning it on asks Windows to create a key credential named after the
  account. Its RSA key is kept by Windows Hello, in the TPM where there is
  one, and is used only after the user verifies.
- The app signs a fixed challenge (`"BlackBoxus v1 windows-hello
  challenge" ‖ account_id`) with it. RSA signatures with PKCS #1 v1.5
  padding are deterministic, so the same signature comes back every time;
  HKDF-SHA-256 turns it into the device key.
- The key set is wrapped with the device key as unlock method 3, and the
  current session token is sealed under the key set, so the app can sync
  after a Hello unlock. Both are stored only in `device-unlock.json` on
  this computer and never uploaded.
- The master password is required again after 14 days without it. Every
  master password unlock restarts the 14 days and stores the new session.
  If the stored session has expired on the server, the app locks and asks
  for the master password.
- Turning it off deletes the file and the Windows key.

Debug builds on Linux can try this with `BLACKBOXUS_FAKE_HELLO=1`, which
replaces Windows Hello with an in-memory key and no user check.

## Importing

"Import passwords" in the sidebar reads a CSV export from another password
manager. The format is recognised from its header row: Bitwarden,
1Password, Chrome, Edge, Brave, Firefox, Safari, LastPass, KeePass,
KeePassXC, Dashlane, NordPass and Proton Pass exports all work.

- The file is chosen in the system's file picker and read in Rust; only
  titles and counts reach the window, shown for checking before anything
  is saved. Files over 20 MB or 10,000 entries are refused.
- Rows become logins (title, username, password, website, one-time code
  secret, notes) or secure notes. Rows with nothing to keep are left out
  and counted.
- Items are written 50 at a time as a chain of log entries, then the vault
  is synced and verified once per batch (`put_new_items` in
  `client-core`). If the server's request limit is reached, the import
  waits and carries on; if another device writes meanwhile, the rest of
  the batch is rebuilt on top of its change.
- Afterwards the app offers to delete the export file, which holds every
  password unencrypted.

Folders, tags, custom fields and attachments are not imported yet.

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

Owners can add people as "Can edit" or "Can view", change anyone's role
(including making them an owner), and remove people. A vault always keeps
at least one owner.

Removing someone follows spec section 7.6: the app records the removal
and a new vault key version in the log, wraps the new key for the owner,
and shares it with every remaining member, each checked against the key
bundle the log pins for them. It then re-encrypts every item under the new
key, so the removed person's old key opens nothing the server now holds.
The server stops letting them download the vault as soon as the removal
is recorded, and refuses changes from anyone whose role does not allow
them. Anything they saw while they were a member may still be in their own
copies, so passwords they could see should be changed.

Members who aren't owners can leave a vault. Writes then pause until an
owner's app replaces the key, which it does by itself on its next sync.

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

## Browser extension

The extension in `apps/extension` fills logins in Chrome, Edge and Brave
(spec section 14). It is off until turned on in Settings:

1. Turning it on registers this app's executable as the browsers' native
   messaging host, for the current Windows user only, and starts listening
   on a named pipe only this user can open.
2. Clicking the BlackBoxus button in the browser the first time asks to
   pair. The app comes to the front and shows a six-digit code; the
   extension shows the same code. Allow it only if they match.
3. From then on, the button lists the logins saved for the page's site,
   and "Fill" fills one. The keyboard shortcut (Alt+Shift+L, changeable at
   `chrome://extensions/shortcuts`) fills the only login for the page, or
   opens the list. Nothing happens while BlackBoxus is locked or closed.

Paired browsers are listed in Settings, where each can be removed. Turning
the extension off, or signing out, forgets them all and removes the
registration.

To load it during development:

```sh
cd apps/extension
npm ci
npm test            # checks the crypto against the shared test vectors
npm run build       # writes the extension to dist/
```

Then open `chrome://extensions`, turn on Developer mode, choose "Load
unpacked" and pick `apps/extension/dist`. The `key` in its manifest gives
it the ID the app allows. A Chrome Web Store listing gets its own ID, which
must be added to `EXTENSION_IDS` in `src-tauri/src/browser/register.rs`.

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
