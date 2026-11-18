# Mac and iPhone apps

Like the Android app, these are the desktop app built for Apple's systems
with Tauri 2: the same Rust code for keys, encryption and the server, and
the same Svelte screens. The Mac app uses the desktop screens; iPhones and
iPads use the phone screens.

**State:** the code is written and type-checks for macOS and iOS. The
**Apple** workflow builds the Mac app and runs the iPhone app in the iOS
Simulator. Nothing is signed yet, so some parts only work once it is
(below).

## What is different on Apple devices

| | Mac | iPhone and iPad |
| --- | --- | --- |
| Secret Key storage | The login keychain | The keychain, "when unlocked, this device only": never in backups or moved to a new device |
| Unlocking without the master password | Touch ID | Face ID or Touch ID |
| Clipboard | Copies are marked concealed (`org.nspasteboard.ConcealedType`), which clipboard managers skip | Through Tauri's clipboard plugin, cleared after 30 seconds without reading it first (iOS would ask the person each time) |
| One-time code setup | Paste the setup key | Paste it, or scan the QR code (Apple's own camera code; the picture stays on the device) |
| Browser extension | Chrome, Edge, Brave, Vivaldi, Chromium and Firefox, if installed | Not on phones |
| Autofill in other apps | The browser extension | Not yet (below) |

### Touch ID and Face ID

The unlock secret is a random 32-byte keychain item in the "data
protection" keychain, with the access control `biometryCurrentSet` and
"when passcode set, this device only". The system hands it over only after
Touch ID or Face ID with the fingers or face enrolled when it was made.
Enrolling another one, or removing the passcode, makes it unreadable for
good, so unlock turns off and the master password is needed (as on
Android). The app derives its device key from an HMAC of a fixed challenge
under that secret (`src/hello.rs`, `apple` module).

On a Mac, the data protection keychain is only open to signed apps, so an
unsigned build hides the Touch ID setting.

### The iPhone screens

The phone screens were made for Android first. On iPhones and iPads
(`src/mobile/ios.ts` and the `html.ios` rules in `mobile.css`):

- **Notch, Dynamic Island, home indicator.** Every screen's top and bottom
  spacing comes from the system's safe areas, so it fits the iPhone SE
  (no notch) up to the Pro Max. In landscape the column stays clear of the
  island and the rounded corners at the sides.
- **Keyboard.** iOS slides the whole page up when the keyboard opens. The
  app's frame is shrunk to the part above the keyboard instead, so headers
  stay put and buttons stay visible, as on Android.
- **Text size.** The system text size (Dynamic Type) is read from Apple's
  body font and applied like Android's text zoom, up to 200%.
- **Going back.** Swiping in from the left edge closes the page or sheet.
- **No rubber-banding** of the whole page, and no zooming into fields.
- **App switcher.** The screens are hidden as soon as the app goes to the
  background, so the app switcher's snapshot shows no vault contents.
- **Wording.** "Face ID" or "Touch ID" and "iPhone" or "iPad" instead of
  "fingerprint" and "phone".

`Info.ios.plist` adds what iOS asks for: why the app uses the camera and
Face ID, light status bar text, and that the app's encryption is exempt
from export paperwork (it only uses standard algorithms for its own data).

## Building

The **Apple** workflow (Actions › Apple › Run workflow) runs on GitHub's
macOS runners. They count about ten times Linux minutes against the monthly
allowance, so it only runs by hand, or when its own file changes.

- **Mac app:** clippy and tests on macOS, then a `.dmg` for Apple silicon,
  ad-hoc signed. The first time, macOS refuses to open it: open System
  Settings › Privacy & Security and choose **Open Anyway**.
- **iPhone app:** clippy for iOS, then `tauri ios init` makes the Xcode
  project, which is built for the Simulator and started on an iPhone SE,
  iPhone 16, iPhone 16 Pro Max and an iPad. Their screenshots are kept on
  the run's page.

On a Mac with Xcode: `npm ci`, `npx tauri ios init`, then `npx tauri ios
dev` for the Simulator or a connected iPhone. With only a free Apple ID,
Xcode can install on your own iPhone, but the app stops opening after 7
days.

## Icons

- iPhone and iPad: `icons/ios`, made from `docs/brand/icon.png` (the
  borderless square; iOS rounds the corners itself).
- Mac: `icons/icon.icns`, the icon's rounded tile on Apple's macOS grid
  (an 824-pixel tile in a 1024-pixel canvas), so it lines up with other
  apps in the Dock.

## Still to do

First, before anyone uses the iPhone app for real:

- **Keep copies off other devices.** Tauri's clipboard plugin sets the
  general pasteboard, which Universal Clipboard shares with your nearby
  Mac and iPad. A small Swift change is needed to copy with
  `localOnly` and a 30-second `expirationDate`, which also clears it while
  the app is in the background (a suspended app's timer doesn't run).
- **Hide the vault in the app switcher, natively.** iOS has nothing like
  Android's screenshot block. The screens hide themselves when the app
  goes to the background (`ios.ts`), but iOS may take its snapshot before the web
  view repaints; a few lines of Swift in the generated app delegate make
  it certain.

These need the Apple Developer Program (99 US dollars a year):

1. **Signing and notarizing the Mac app** with a Developer ID, so it opens
   without the warning and Touch ID unlock works. Set
   `bundle.macOS.signingIdentity` and the notarization secrets in the
   workflow.
2. **iPhone builds for real devices**, through TestFlight: a development
   team in `bundle.iOS.developmentTeam`, then `tauri ios build` and an
   upload to App Store Connect.
3. **Autofill on iPhone and iPad.** iOS runs password autofill as a
   separate small app (a Credential Provider extension) with tight memory
   limits. It can't ask the main app the way Android's service does, so it
   needs its own copy of the Rust core and the vaults kept in a shared,
   encrypted app group. Passkeys build on the same extension.
4. **Safari extension.** Safari's extensions ship inside a Mac app built
   with Xcode, so this comes after signing.
5. **Intel Macs:** a second build (`x86_64-apple-darwin`) or a universal
   one.
