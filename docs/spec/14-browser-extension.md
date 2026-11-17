# 14. Browser Extension

## 14.1 Overview

The browser extension fills logins into web pages. It holds no keys and no copy of any vault: it asks the desktop app on the same computer for one login at a time, when the user asks it to fill, and the app answers only while it is unlocked, only an extension the user paired, and only with logins saved for the page's site.

```
page ◄── fill ── extension ── native messaging ──► host ── local socket ──► desktop app
                (service worker)                (the app's own executable,
                                                 started by the browser)
```

Chromium-based browsers (Chrome, Edge, Brave, Chromium) are supported. Firefox uses a different registration and is not supported yet.

## 14.2 Transport

**Native messaging host.** The app registers a host named `com.blackboxus.desktop`. Its manifest names the app's own executable and allows only the extension's ID; the browser refuses every other extension. Chromium browsers and Firefox get separate manifests, since Chromium lists allowed extensions as `allowed_origins` (`chrome-extension://<id>/`) and Firefox as `allowed_extensions` (the add-on ID declared in the Firefox build's `browser_specific_settings`). On Windows each manifest's path is set, per user, under each browser's `NativeMessagingHosts` registry key (`Software\Mozilla\NativeMessagingHosts` for Firefox); no administrator rights are needed. Registration happens when the user turns on the browser extension in Settings, again at each start (an update may move the executable), and is removed when they turn it off.

When the browser starts the executable with an extension origin (`chrome-extension://…`) or an allowed Firefox add-on ID as an argument, it does nothing but relay messages between its standard input and output and the app's local socket. If the app is not running, it answers every message with `{"t":"error","code":"app_closed"}`.

**Local socket.** On Windows, a named pipe per Windows user, `\\.\pipe\blackboxus-browser-<user>`, whose access list allows only its owner and the system, and which refuses remote clients. Elsewhere (for development), a socket file in the user's runtime directory with mode `0600`.

**Framing.** Each message is UTF-8 JSON preceded by its length as a little-endian `u32`, as native messaging frames it. The app reads at most 64 KiB per message and writes at most 1 MiB.

## 14.3 Pairing

The extension and the app agree a 256-bit key once, when the user approves the browser in the app.

1. The extension generates a random 16-byte `id` and an ephemeral P-256 key pair, and sends `{"t":"pair","id","key","browser"}` (`key` is the uncompressed public key, 65 bytes; binary values are base64url without padding).
2. The app generates its own ephemeral key pair and answers `{"t":"pair","key"}`. Both sides compute:

```
shared     = ECDH-P256(own private key, other public key)          (32 bytes)
transcript = SHA-256("BlackBoxus v1 browser-pair" ‖ id ‖ extension_key ‖ app_key)
okm        = HKDF-SHA-256(salt = transcript, IKM = shared,
                          info = "BlackBoxus v1 browser-pair", L = 36)
key        = okm[0..32]
code       = u32be(okm[32..36]) mod 1 000 000, as six digits
```

3. Both show `code`. The app asks the user whether to allow the named browser, and to allow it only if the extension shows the same code. A program in the middle of the exchange would produce different codes on each side.
4. If the user allows it within two minutes, the app stores `id` and `key` in the operating system's credential store and answers `{"t":"paired"}`; otherwise `{"t":"error","code":"denied"}`. The extension stores `key` as a non-extractable Web Crypto key, so its bytes are never available to script again.

The app keeps one pairing per browser profile. Removing one in Settings, signing out, or turning the browser extension off forgets them.

## 14.4 Requests

Every later message is sealed with AES-256-GCM under the pairing key, with a random 96-bit nonce:

```
request  = {"t":"req","id","n":nonce,"c":AES-GCM(key, nonce, json, aad = "BlackBoxus v1 browser-request"  ‖ id)}
response = {"t":"res","n":nonce,      "c":AES-GCM(key, nonce, json, aad = "BlackBoxus v1 browser-response" ‖ id)}
```

A request the app cannot open is answered `{"t":"error","code":"unpaired"}`, and the extension forgets its pairing. The requests are:

| Request | Answer |
| --- | --- |
| `{"op":"status"}` | `{"unlocked","account"}` |
| `{"op":"logins","url"}` | `{"logins":[{"vault","vault_name","item","title","username"}]}`: logins whose website matches `url` (14.5), at most 50, no secrets. |
| `{"op":"fill","url","vault","item"}` | `{"origin","username","password","totp"}`: the login's username, password and current one-time code, if it still matches `url`. `origin` is the page origin the extension must check before filling. |

While the app is locked, `logins` and `fill` answer `{"error":"locked"}`. A `fill` for a login that does not match the page answers `{"error":"no_match"}`: the app checks again rather than trusting the extension's choice.

Replaying a recorded request gains nothing: requests only read, and every answer is sealed to the pairing key.

## 14.5 Which logins match a page

A login matches a page if one of its website fields names the same site:

- Only `https` and `http` pages are filled. A website saved without a scheme is read as `https`.
- Hosts with a registrable domain match if their registrable domains are equal, found with the Public Suffix List. So `accounts.example.com` matches `www.example.com`, but `alice.github.io` does not match `mallory.github.io`, and nothing matches a bare public suffix such as `co.uk`.
- IP addresses and single-label hosts such as `localhost` match only the same host and port.
- A port saved with the website must match the page's.
- A login saved for `https` is never offered to an `http` page. An `http` page is marked as not secure in the popup.

## 14.6 Filling

Filling starts only from a click in the extension's toolbar popup or from its keyboard shortcut. The extension injects no element into pages, so a page cannot hide, cover or restyle anything of the extension's to trick the user into a click (the "DOM-based extension clickjacking" reported against several password managers in 2025).

The extension uses the `activeTab` permission, which lets it act on the current tab only after the user's click or shortcut. It has no content scripts and no host permissions. To fill, it runs one function in the page's top frame, in the extension's isolated world, which:

- does nothing unless the page's origin is still the `origin` the app approved;
- fills only fields that are visible: not hidden, transparent, off-screen, disabled or read-only;
- fills the password into the first visible password field, and the username into the nearest visible text field before it; on a page with only a username field, the username; on a page with only a one-time code field, the code.

The password is requested at the moment of filling and is not kept by the extension.

## 14.7 Security considerations

- **Other extensions and web pages** cannot reach the host: the browser starts it only for the allowed extension ID, and the extension accepts messages only from its own popup.
- **Other users of the computer** cannot open the named pipe.
- **Programs running as the same user** can already read the app's memory and the browser's storage. The pairing key, kept in the credential store, does not protect against them, and nothing on the computer can.
- **Phishing.** Matching by registrable domain means a look-alike domain gets no offer, which is itself a warning sign. A user can still copy a password by hand.
- **Subdomains** of a site share its logins. A site that hosts other people's pages on its own subdomains, and is not in the Public Suffix List, could have them offered there; users can save a more specific address with a port, or keep such logins in a separate vault.
- **Compromised page after filling.** Whatever is filled into a page can be read by that page's script, as with any password entry.

## 14.8 Tests

`docs/spec/vectors/14-browser.json` holds a pairing exchange with fixed keys and a sealed request and answer. It is checked by the app (Rust), by the extension's own tests (Web Crypto, under Node.js), and independently by `tools/vectors/verify_browser.py` (OpenSSL). The app's tests also cover matching, framing and message parsing. The whole path has been run end to end with Chromium, the extension, the app and a local server: pairing with the code, listing and filling a login, nothing offered on another origin, and nothing while locked.
