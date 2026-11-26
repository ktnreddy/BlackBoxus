# Roadmap

What BlackBoxus has, what similar apps have that it doesn't, and when each
gap is planned. Updated 26 November 2026.

## What BlackBoxus already has

- Logins, cards, notes, identities and API credentials, with custom fields
- One-time codes (TOTP), password generator, password health and breach check
- Vaults shared with other people, a trusted contact for emergencies, a
  recovery key and an Emergency Kit
- Fingerprint and Windows Hello unlock, auto-lock, clipboard clearing
- Works offline: changes are kept and synced later, with conflict handling
- Import from CSV and BlackBoxus exports; encrypted and CSV export
- Android autofill (including saving new logins), browser extensions
- Post-quantum encryption (ML-KEM, ML-DSA) and key transparency, which few
  password managers have

## Compared with others

| Feature | BlackBoxus | Bitwarden | 1Password | Proton Pass | Google |
| --- | --- | --- | --- | --- | --- |
| Logins listed under the field, fill in one tap | 0.2.1 | Yes | Yes | Yes | Yes |
| Unlock inside the fill sheet with a fingerprint | 1.0 | Yes | Yes | Yes | Yes |
| Trash / recently deleted | 0.3 | Yes | Yes | Yes | No |
| Password history per login | 0.3 | Yes | Yes | Yes | No |
| Favourites | 0.3 | Yes | Yes | Yes | No |
| Folders or tags | 0.3 | Folders | Tags | Vaults | No |
| Sort and filter the list | 0.3 | Yes | Yes | Yes | Partly |
| Archive items (hidden from fill) | 0.4 | Yes | Yes | No | No |
| File attachments | 0.4 | Yes | Yes | Yes | No |
| Share one item by link, with expiry | 0.4 | Yes (Send) | Yes | Yes | No |
| Password expiry reminders | 0.4 | No | Yes | No | No |
| Signed-in devices list, sign out others | 0.4 | Yes | Yes | Yes | Yes |
| Passkeys | 1.0 | Yes | Yes | Yes | Yes |
| Move passwords and passkeys between apps (Credential Exchange) | 1.0 | Yes | Yes | No | Yes |
| Import KeePass, 1Password, Bitwarden files directly | 0.4 | Yes | Yes | Yes | CSV |
| Inline fill menu and auto-save in the browser extension | 0.4 | Yes | Yes | Yes | Yes |
| Email aliases | Not planned | Via partners | Yes | Yes | No |
| Travel mode | Later | No | Yes | No | No |
| SSH keys | Later | Yes | Yes | No | No |

## Releases

### 0.2.1: autofill that works, and speed

- Fixed: choosing a login didn't fill anything. Android expects a whole
  set of choices back from the picker; BlackBoxus sent back one login.
- Logins saved for the site are listed under the field and fill in one
  tap, like Google's; "Fill with BlackBoxus" opens the full list.
- When BlackBoxus is locked, "Unlock BlackBoxus" opens it and brings the
  person straight back to the form, which fills or saves by itself.
- The fill and save screens are sheets over the app being filled.
- "Sync now" on the phone (vault screen and Settings).
- Server (done 26 November): the database moved from Western North
  America to Asia-Pacific (Singapore), so requests from India no longer
  cross the Pacific, and the server runs next to it.

### 0.3: everyday basics (new item format, schema version 2)

Needs every device on 0.2.0 or later first (they keep items saved in the
new format instead of failing the vault).

- Trash, kept for 30 days; password history per login; favourites
- Folders (or tags), sorting and filters
- One request per sync instead of one per vault and member

### 0.4: catching up

- Attachments, share-by-link, archive, expiry reminders
- Devices list with "sign out other devices"
- Direct import from KeePass, 1Password and Bitwarden files
- Browser extension: inline fill menu and auto-save

### 1.0: native apps

- Android in Kotlin with Jetpack Compose, iPhone and iPad in SwiftUI,
  using the same Rust core for all encryption and sync
- Passkeys (see `docs/design/passkeys.md`), fingerprint unlock inside the
  fill sheet, Credential Exchange import and export
