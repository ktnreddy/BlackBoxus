# Android app

The Android app is the desktop app built for phones. Tauri 2 compiles the
same Rust code (`apps/desktop/src-tauri`) into a library that Android loads,
and shows the same Svelte screens in Android's WebView. Everything that
touches keys stays in Rust, exactly as on the desktop, so the two apps
cannot drift apart in how they encrypt or check the server.

It needs Android 9 or later and runs on 64-bit ARM phones, which is nearly
every phone sold since 2017.

## What is different on a phone

| | Desktop | Android |
| --- | --- | --- |
| Layout | Vault list, items and the open item side by side | One pane at a time, with the vault menu in a drawer; the back gesture steps back |
| Secret Key storage | Windows Credential Manager or the Secret Service | Encrypted with a key held in the Android Keystore (in the phone's secure hardware where it has one), stored in the app's private preferences |
| Clipboard | Kept out of clipboard history and cloud sync | Marked sensitive, so Android shows dots instead of the text in its clipboard preview |
| Screenshots | Allowed | Blocked: the app sets `FLAG_SECURE`, which also hides it in the recent-apps view and from screen recording and casting |
| Backups | Not applicable | Turned off: Android's cloud backup and device-to-device transfer skip the app entirely. The vault copies on the phone are sealed with keys that never leave it, so a restored copy would be useless anyway; vaults come back from the server when you sign in |
| Emergency Kit | Print it or save it as a PDF | Write it down: phones can't print from the app, and screenshots are blocked |
| Import | Choose a CSV file; the app can delete it afterwards | Choose a file through Android's file picker; the app can only read it, so it reminds you to delete it in your Files app |
| Unlocking without the master password | Windows Hello | Fingerprint, with a Keystore key that only works after a strong biometric check. Adding a fingerprint in the phone's settings invalidates the key, so fingerprint unlock turns off until you turn it on again |
| Filling logins | The browser extension | Android's autofill service, in browsers and other apps (below) |
| One-time code setup | Paste the setup key | Paste it, or scan the site's QR code with the camera |

Clearing the clipboard 30 seconds after a copy works as on the desktop,
with one Android rule: apps can only read the clipboard while they are on
screen. If BlackBoxus is in the background when the 30 seconds are up, it
clears the clipboard without checking whether you copied something else
since, because leaving a password there is worse than losing a later copy.

## The project

| Path | What it is |
| --- | --- |
| `apps/desktop/src-tauri/gen/android` | The Android Studio project. Made once by `tauri android init`, then kept in the repository with these changes: |
| `app/src/main/AndroidManifest.xml` | The internet permission (the QR scanner adds the camera); backups off; the autofill service and its picker |
| `app/src/main/res/xml/data_extraction_rules.xml` | Excludes everything from cloud backup and device transfer |
| `app/src/main/java/.../MainActivity.kt` | Sets `FLAG_SECURE` |
| `app/src/main/java/.../Autofill*.kt`, `BlackBoxusAutofillService.kt` | Autofill in other apps (below) |
| `app/src/main/res/mipmap-*` | The launcher icons, made from `docs/brand` |
| `app/build.gradle.kts` | Android 9 minimum; signs release builds when `keystore.properties` exists |

## Autofill in other apps

Choose BlackBoxus in **Settings › Autofill** in the app (it opens the
phone's setting). Then tapping a username or password field shows **Fill
with BlackBoxus**. In Chrome, also turn on **Settings › Autofill services
› Autofill using another service**.

- The offer itself holds nothing from the vaults. Choosing it opens a
  picker (`AutofillPickerActivity`), and only the login picked there goes
  back to Android.
- The Kotlin code holds no vault data either. It asks the Rust side
  through a small Tauri plugin (`AutofillPlugin`, `src/autofill.rs`):
  Rust waits for the next question, answers it and waits again. So the app
  must be running and unlocked; otherwise the picker offers to open it.
- In a browser on the list in `AutofillFields.kt`, only logins for the
  page's site are listed, with the browser extension's matching rules
  (same registrable domain; a login saved for `https` is never offered to
  an `http` page). Rust checks the match again before handing over the
  password.
- Any app can claim a web domain for its fields, so web domains from other
  apps are ignored. There, nothing is matched automatically: the picker
  names the app and you search for the login yourself.
- On Android 11 and later, keyboards that support it (Gboard, Samsung
  Keyboard) show the offer in their suggestion strip instead of a dropdown
  (`androidx.autofill`'s inline suggestion template).
- **Saving.** When a form with a password field is sent, Android asks
  "Save to BlackBoxus?". Choosing Save keeps what was typed in memory only
  (`PendingSave`, for five minutes) and opens `AutofillSaveActivity`,
  which asks the person to confirm the name. Rust then updates the login
  for the same site (or, in apps, the same title) and username, or makes a
  new one in the first vault the account owns. If BlackBoxus is locked,
  the person unlocks it and comes back, and the save goes through then.
- Settings › Autofill shows what happened the last time Android asked
  (which app, and whether the offer was shown), and whether Chrome is set
  to use another autofill service, read from Chrome's documented content
  provider. Only the package name, time and outcome are kept.

The Rust side switches by platform: `browser_mobile.rs` stands in for the
browser bridge, `clipboard_mobile.rs` for the clipboard, and `storage.rs`
picks the Android Keystore store. The window learns it is on a phone from
`mobile` in the app status.

## Getting the app without building it

Every push that changes the app runs the **Desktop** workflow on GitHub,
whose **Android app** job builds an APK. Open the run under **Actions**,
download `blackboxus-android-apk`, unzip it, copy the `.apk` to your phone
and open it there. Android asks you to allow installing apps from that
source the first time.

Without a signing key set up (below), each run signs its APK with a new,
throwaway key. Android refuses to install an APK over one signed with a
different key, so uninstall the old app first. That also deletes the
phone's copy of your vaults and Secret Key, and you'll need your Emergency
Kit to sign in again.

## Building it yourself

You need, once:

1. Android Studio, which installs the Android SDK.
2. In Android Studio's SDK Manager, under **SDK Tools**: the **NDK (Side
   by side)** and **Android SDK Command-line Tools**.
3. Java 17 or later (Android Studio's own works).
4. The Rust targets: `rustup target add aarch64-linux-android x86_64-linux-android`.
5. Environment variables pointing at the SDK and NDK. On Windows:

   ```powershell
   [Environment]::SetEnvironmentVariable("ANDROID_HOME", "$env:LocalAppData\Android\Sdk", "User")
   [Environment]::SetEnvironmentVariable("NDK_HOME", "$env:LocalAppData\Android\Sdk\ndk\<version>", "User")
   [Environment]::SetEnvironmentVariable("JAVA_HOME", "C:\Program Files\Android\Android Studio\jbr", "User")
   ```

   On Linux or macOS, `export` the same three in your shell profile.

Then, from `apps/desktop`:

```sh
npm ci
npx tauri android dev            # runs on a connected phone or a running emulator
npx tauri android build --apk --target aarch64
```

`android dev` opens the app with live reload of the screens. On a real
phone, connected by USB with developer options and USB debugging on, Tauri
points it at this computer's address; the phone and computer must be on the
same network. Debug builds of the Rust code are slow at stretching the
master password, so unlocking takes several seconds there; release builds
take about a second.

`android build` puts the APK under
`src-tauri/gen/android/app/build/outputs/apk/`. Add `--aab` instead of
`--apk` for the bundle Google Play wants.

## Signing

Android only installs signed apps, and only installs an update signed with
the same key as the app already on the phone. Make the key once and keep it
safe; losing it means users must uninstall and reinstall to get updates.

```sh
keytool -genkeypair -keystore blackboxus-upload.jks -storetype PKCS12 -alias upload \
  -keyalg RSA -keysize 3072 -validity 10000
```

Keep `blackboxus-upload.jks` outside the repository (`.gitignore` refuses
`*.jks` and `keystore.properties` anyway). To sign local builds, create
`apps/desktop/src-tauri/gen/android/keystore.properties`:

```properties
storeFile=/full/path/to/blackboxus-upload.jks
keyAlias=upload
password=<the password you chose>
```

To have GitHub sign the APKs it builds, add two repository secrets under
**Settings → Secrets and variables → Actions**:

- `ANDROID_KEY_BASE64`: the key file in base64 (`base64 -w0 blackboxus-upload.jks`
  on Linux, `[Convert]::ToBase64String([IO.File]::ReadAllBytes("blackboxus-upload.jks"))`
  in PowerShell).
- `ANDROID_KEY_PASSWORD`: its password.

## Publishing

For Google Play: a developer account costs a one-off 25 US dollars. New
personal accounts must run a closed test with at least 12 testers for 14
days before the app can go public. Upload the `.aab`, and let Play App
Signing hold the final signing key; your key then only proves uploads come
from you. The store listing needs a privacy policy link (the website's
`/privacy` page) and the Data safety form: BlackBoxus collects an email
address for the account, and everything else it sends is end-to-end
encrypted.

Without Play, the APK from GitHub can be shared directly, or listed in
F-Droid, which builds from source and needs the app to be free software
with no proprietary dependencies. The QR scanner uses Google's ML Kit
(through Play services), which F-Droid does not accept, so an F-Droid
build would need the scanner left out or replaced first. Without Play
services the scanner doesn't work; pasting the setup key still does.

## Still to do

- **Passkeys**, through Android's Credential Manager (see
  `docs/design/passkeys.md`).
