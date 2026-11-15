# 10. Devices and Unlocking

## 10.1 Overview

A user's devices hold the account's Secret Key and, while unlocked, its key set. This section covers:

- adding a new device, either by typing the Secret Key or by scanning a QR code from a device that is already signed in (10.3);
- unlocking quickly with biometrics or a PIN through a **device key** held in secure hardware (10.4);
- unlocking with a **passkey**, where the passkey actually decrypts the key set (10.5).

Every unlock method holds its own wrapped copy of the key set (Section 5.4). The master password and Secret Key always remain able to unlock the account.

## 10.2 Signing in on a new device manually

The user enters their email address, master password and Secret Key, and the client follows Section 3.8 and Section 4.5. The client then stores the Secret Key in the platform's secure storage.

## 10.3 Adding a device with a QR code

This transfers the Secret Key and account details from a signed-in device (A) to a new device (B) without the server ever seeing them. The user still enters the master password on B.

1. A generates `session_id = random(16)` and `secret = random(32)`, and shows a QR code containing:
   ```
   "blackboxus-enrol:1:" ‖ hex(session_id ‖ secret)          (lower-case hex)
   ```
2. B scans it.
3. A encrypts the **enrolment payload** and uploads it to the server under `session_id`:
   ```
   payload = u16be(1) ‖ account_id ‖ secret_key
           ‖ u8(len(email)) ‖ email ‖ u8(len(server)) ‖ server
           ‖ u16be(len(sth)) ‖ sth

   key     = HKDF-SHA-256(salt = empty, IKM = secret,
                          info = "BlackBoxus v1 enrolment" ‖ session_id, L = 32)
   aad     = "BlackBoxus v1 enrolment" ‖ session_id
   sealed  = nonce ‖ XChaCha20-Poly1305(key, nonce, payload, aad)
   ```
   `email` and `server` are the canonical identities of Section 4.3. `sth` is A's latest signed key-transparency tree head (Section 9.3), or empty.
4. B downloads `sealed` by `session_id`, decrypts it, checks that `email` and `server` are canonical, and continues as in 10.2 using the received Secret Key.
5. B compares the received tree head with the log, as in Section 9.4. This lets two devices of the same account detect a split view of the key transparency log.

The server MUST delete the transfer after one download or after 300 seconds, whichever comes first. A MUST only show the QR code after the user asks to add a device, and SHOULD show it on screen only (not in a screenshot or notification).

Someone who photographs the QR code learns the Secret Key, but still needs the master password, which is why the transfer does not include it.

## 10.4 Device keys (biometrics and PIN)

To avoid typing the master password every time, a device can unlock with a **device key**:

1. After a full unlock, the client generates `device_key = random(32)` and wraps the key set with it using method 3 (Section 5.4).
2. The device key is stored in the platform's secure element (Secure Enclave on Apple devices, StrongBox or TEE-backed Keystore on Android, TPM on Windows), protected by a biometric or PIN check, and marked non-exportable where the platform allows.
3. The wrapped copy is stored **only on the device**, never uploaded.

Where the secure element cannot store an arbitrary secret but can sign with a non-exportable key behind a user check, the device key MAY instead be derived from a deterministic signature over a fixed challenge. On Windows, Windows Hello key credentials sign with RSA and PKCS #1 v1.5 padding, which is deterministic:

```
challenge  = "BlackBoxus v1 windows-hello challenge" ‖ account_id
device_key = HKDF-SHA-256(salt = empty, IKM = Sign(challenge),
                          info = "BlackBoxus v1 windows-hello device-key", L = 32)
```

So that the device can sync after such an unlock, the client MAY keep its current session token sealed under the key set with the local-storage sealing of Section 6.8 (context `"device-unlock session"`), and replace it after every master password unlock. The server still expires sessions as usual (Section 12).

Clients MUST ask for the master password again after 14 days without one, after a device restart if the platform supports it, and whenever the secure element reports that enrolled biometrics changed. A device key MUST be deleted when the user signs out.

## 10.5 Passkey unlock (WebAuthn PRF)

A passkey with the WebAuthn PRF extension can produce a stable secret that only exists inside the authenticator. BlackBoxus uses it as a real decryption key, not merely a login check.

```
prf_input    = SHA-256("BlackBoxus v1 passkey-prf-input" ‖ account_id)
prf_output   = WebAuthn PRF output for prf_input (prf.eval.first)   (32 bytes)
wrapping_key = HKDF-SHA-256(salt = SHA-256(credential_id), IKM = prf_output,
                            info = "BlackBoxus v1 passkey-unlock", L = 32)
```

The key set is wrapped with `wrapping_key` using method 2 and uploaded, so the passkey works on any device where it is available. The server stores one wrapped copy per credential ID.

- The PRF output MUST be used only for this derivation and erased immediately.
- Credentials that do not support PRF MUST NOT be offered as an unlock method.
- Because a passkey is bound to its website domain, passkey unlock SHOULD only be offered to users once the service has a permanent domain.

Passkey unlock decrypts the key set. Logging in to the server still uses OPAQUE (Section 4) or an existing session; a server-side passkey login can be added in a later version.

## 10.6 Security considerations

- **Stolen unlocked device.** No unlock method protects data on a device that is already unlocked and under an attacker's control; this is outside the threat model in `docs/architecture.md`. Auto-lock limits the window.
- **Stolen locked device.** The device key never leaves the secure element, and the master-password path still requires the master password.
- **Lost passkey.** Removing a passkey means deleting its wrapped copy on the server. Because the key set itself is unchanged, a thief who already copied that wrapped copy and holds the passkey could still use it; after a suspected compromise the user SHOULD replace the key set (Section 5.6).

## 10.7 Test vectors

[`vectors/10-devices.json`](vectors/10-devices.json) contains a QR code, an encrypted enrolment transfer and a passkey wrapping key made from fixed inputs. They are checked independently with libsodium by [`tools/vectors/verify_devices.py`](../../tools/vectors/verify_devices.py).
