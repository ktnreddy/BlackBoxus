# Passkeys: design

Status: proposal, no code yet. Targets the release after the item format
change (schema version 2, see "Order of work").

## What we want

People can save passkeys to BlackBoxus and sign in with them on every
device where they use BlackBoxus, the same way they use its passwords:
end-to-end encrypted, synced, shareable through vaults, and exportable.

## How passkeys work, in one paragraph

A passkey is a key pair made for one website (the *relying party*, named
by its *RP ID*, such as `github.com`). The site keeps the public key; the
password manager keeps the private key. To sign in, the site sends a
random challenge and the manager signs it, after checking the person is
present (a fingerprint, the device PIN, or an unlocked app). There is no
secret the site could leak, and a passkey can't be phished, because the
browser or operating system tells the manager which site is asking and
the manager only answers for the passkey's own RP ID.

## Where BlackBoxus must plug in

| Platform | System interface | Needs |
| --- | --- | --- |
| Android 14+ | Credential Manager provider (`androidx.credentials` `CredentialProviderService`) | A provider service and two activities (create, get). The person enables BlackBoxus in Settings › Passwords, passkeys & autofill. |
| iOS 17+ / macOS 14+ | `ASCredentialProviderExtension` with passkey support | An app extension. It runs in its own process, so it needs the vault keys in a way that doesn't need the main app running (see "Open questions"). |
| Windows 11 | The WebAuthn plugin authenticator interface (`webauthn.h`) | A plugin registered with Windows; the person turns it on in Settings › Accounts › Passkeys › Advanced options. Microsoft's sample is a packaged (MSIX) WinUI app; we need to confirm what an unpackaged Tauri app must do. |
| Browsers on desktop | Our browser extension | The extension answers `navigator.credentials.create()` and `.get()` on pages, and asks the desktop app over the existing native-messaging channel (spec section 14). Works on Linux and older Windows too. |

Android and the browser extension come first: both reuse code we already
have (the autofill service's question broker; the extension's pairing).

## Storage

A passkey is a new item type, `Passkey`, with new field kinds:

- `RpId`: the site, such as `github.com`.
- `CredentialId`: random, 16 bytes, base64url.
- `UserHandle`: the site's ID for the account, base64url.
- `UserName` / `UserDisplayName`: shown in the picker.
- `PrivateKey`: a P-256 (ES256) private key, PKCS#8, concealed. Ed25519
  (EdDSA) too, for sites that ask for it.
- `Created`: when it was made.

Like every item, it is encrypted on the device with the vault key before
it is synced, so the server never sees a private key. A passkey can sit
next to the password login for the same site; the item view links them
by RP ID.

Signature counter: always 0. Synced passkeys can't keep a counter in
step across devices, and WebAuthn allows 0 to mean "no counter".

Flags: backup-eligible and backed-up are both set, so sites know the
passkey is synced.

## Signing in

1. The system or extension asks for a passkey for an RP ID and passes the
   challenge (as `clientDataHash` on Android, or `clientDataJSON` from the
   extension).
2. If the vaults are locked, BlackBoxus shows its unlock step first.
3. The person picks a passkey for that RP ID. Only passkeys whose RP ID
   matches what the system says the caller is are listed, the same rule as
   autofill's site matching. On Android, origins from browsers are only
   trusted for browsers on an allowlist (Google publishes one we can use),
   and other apps' origins are derived from their signing certificate.
4. Person present: the device's biometric or PIN prompt, always, even if
   the vault is unlocked (user verification, `uv`).
5. The Rust core signs `authenticatorData ‖ clientDataHash` with the
   private key and returns the assertion. The private key never leaves
   Rust memory, and is erased after use.

## Creating a passkey

1. The site asks to create one; the system offers BlackBoxus.
2. The person chooses a vault (default: the first one they own), after
   user verification.
3. Rust makes the key pair, saves the item, and returns the attestation
   (format `none`; we don't attest to the authenticator's model).
4. If saving fails (offline), the item is kept in the offline queue like
   any other change and the site still gets its passkey.

## Sharing, export and other managers

- Shared vaults share passkeys like other items. Removing someone from a
  vault rotates its key (spec section 7.6), but they may have copied a
  private key while they had access, so the app should suggest replacing
  shared passkeys after removing a member.
- Our encrypted export (spec section 6.9) includes passkeys.
- For moving to and from other managers, the FIDO Alliance's Credential
  Exchange Format (CXF) is the standard; Apple ships it in iOS/macOS 26.
  We read and write CXF files when it is final.

## Order of work

1. Item schema version 2 (already planned for trash, password history
   and favourites), adding the `Passkey` type and its fields. Clients from
   v0.1.1 on keep items they can't read instead of failing the vault.
2. Rust: key generation, signing, WebAuthn data (authenticatorData,
   attestation object, CBOR/COSE keys) with test vectors from the WebAuthn
   specification. Use RustCrypto `p256` and `ed25519-dalek`; no custom
   crypto.
3. Android provider (Credential Manager), then the browser extension.
4. iOS/macOS extension and Windows plugin, after the open questions.

## Open questions

- iOS/macOS extensions run without the main app. They need the vault keys:
  either the person unlocks in the extension (master password or Face ID
  unlocking a key in the Keychain shared with the app), or the app leaves
  a short-lived key in the shared Keychain. The first is safer; decide
  before building.
- Windows: whether the plugin authenticator needs package identity
  (MSIX). If it does, the Windows build needs an MSIX package as well as
  the installer.
- Whether to offer "Use BlackBoxus for passwords too" in Android's
  Credential Manager (password credentials), on top of autofill.

## Sources

- Android: [Integrate Credential Manager with your credential provider solution](https://developer.android.com/identity/sign-in/credential-provider)
- Windows: [Third-party passkey managers](https://learn.microsoft.com/en-us/windows/apps/develop/security/third-party)
- FIDO: [Credential Exchange Format](https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html)
