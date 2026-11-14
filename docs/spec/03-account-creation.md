# 3. Account Creation and Key Derivation

## 3.1 Overview

A user's encryption keys are derived from two secrets:

1. the **master password**, which the user remembers, and
2. the **Secret Key**, 128 random bits generated on the user's first device, which never leaves the user's devices and Emergency Kit.

Combining them means a copy of everything on the server cannot be attacked by guessing passwords: an attacker would also need to guess 128 random bits. The master password still protects the vault if a device and its stored Secret Key are stolen.

From the two secrets, the client derives two independent 32-byte values:

| Value | Used for | Ever sent to the server? |
| --- | --- | --- |
| Account Unlock Key (AUK) | Decrypting the account key set (Section 5) | Never |
| OPAQUE password (OPW) | Logging in with OPAQUE (Section 4) | Never; OPAQUE does not reveal it |

## 3.2 Secret Key

### Generation

```
sk = random(16)
```

The Secret Key MUST be generated on the client. It MUST NOT be sent to the server, in any form.

### Display format

The Secret Key is shown to users as:

```
B1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX
```

where the 28 characters are 26 characters of key followed by 2 characters of checksum, using the Crockford Base32 alphabet:

```
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

Encoding:

1. Interpret `sk` as a 128-bit unsigned big-endian integer and write it as exactly 26 base-32 digits, most significant first. Because 26 × 5 = 130 bits, the top 2 bits are zero and the first digit is always between `0` and `7`.
2. Compute `h = SHA-256("BlackBoxus v1 secret-key checksum" ‖ sk)`. Take the first 10 bits of `h` and write them as 2 base-32 digits, most significant first.
3. Join the 28 digits into four groups of seven, separated by `-`, and prefix `B1-`.

The `B1` prefix identifies the format and protocol version.

### Parsing

To accept a Secret Key typed by a user, a client MUST:

1. remove all spaces, tabs and `-` characters;
2. convert to upper case;
3. require and remove a leading `B1`;
4. map `O` to `0`, and `I` and `L` to `1`;
5. require exactly 28 characters, all from the alphabet above;
6. require that the first character is `0`–`7`;
7. decode the key and recompute the checksum; reject the input if it does not match.

The checksum detects typing mistakes. It is not a security mechanism.

## 3.3 Master password

### Normalisation

Before any use, the master password MUST be:

1. normalised to Unicode NFKC, then
2. encoded as UTF-8.

This makes a password typed on different keyboards and operating systems produce the same bytes. Leading and trailing spaces MUST NOT be removed.

After normalisation the password MUST be non-empty and at most 1024 bytes.

### Policy for new passwords

When a user creates or changes a master password, the client:

- MUST require at least 12 characters (Unicode scalar values) after normalisation;
- SHOULD recommend a passphrase of 15 characters or more;
- SHOULD reject passwords found in known breaches, using the Have I Been Pwned k-anonymity range API so that the password itself is never sent;
- MUST NOT impose composition rules (such as "one digit and one symbol").

These rules apply only when a password is set. Unlocking with an existing password applies only the normalisation rules.

## 3.4 Argon2id parameters

Each account stores one set of Argon2id parameters and a 16-byte random salt, both chosen by the client at account creation:

| Parameter | Default | Minimum | Maximum |
| --- | --- | --- | --- |
| Memory `m` (KiB) | 131072 (128 MiB) | 65536 (64 MiB) | 1048576 (1 GiB) |
| Passes `t` | 4 | 3 | 10 |
| Lanes `p` | 4 | 1 | 8 |
| Output length | 32 bytes | fixed | fixed |
| Salt | `random(16)` | fixed length | fixed length |

The server stores the parameters and salt and returns them when a device signs in. **The server is untrusted**, so before running Argon2id a client MUST check every parameter against the minimum and maximum above and refuse to continue if any is out of range:

- the minimums stop a malicious server from weakening the derivation;
- the maximums stop a malicious server from making clients exhaust their memory or battery.

Clients MUST create accounts with the default parameters unless the user explicitly chooses others, and SHOULD warn that doing so lets anyone who asks the server learn that the address has an account, because unknown addresses are answered with the defaults (3.8).

The default of 128 MiB is more than six times the OWASP minimum while still fitting the memory limits of mobile devices. Password-manager extensions on mobile operating systems have strict memory caps; they unlock with a device key (Section 10) rather than by running Argon2id.

## 3.5 Two-secret key derivation

Inputs: normalised password `P`, Secret Key `sk`, account salt `salt`, and validated parameters `m`, `t`, `p`.

```
pw   = Argon2id(password = P, salt = salt, m, t, p, length = 32)
prk  = HKDF-Extract(salt = salt, IKM = pw ‖ sk)
AUK  = HKDF-Expand(prk, "BlackBoxus v1 account-unlock-key", 32)
OPW  = HKDF-Expand(prk, "BlackBoxus v1 opaque-password",   32)
```

- `pw`, `prk`, `AUK` and `OPW` are secret and MUST be erased after use.
- The Secret Key is combined after stretching. It already has 128 bits of entropy, so it needs no stretching.
- `OPW` is used as the password input to OPAQUE. Because it is already high-entropy, OPAQUE's own key-stretching function is set to the identity (Section 4).
- `AUK` and `OPW` are independent: learning one reveals nothing about the other.

## 3.6 Creating an account

1. Generate `sk = random(16)` and `salt = random(16)`, and select the default Argon2id parameters.
2. Normalise the chosen master password and apply the policy in 3.3.
3. Derive `AUK` and `OPW` as in 3.5.
4. Generate the account key set and wrap it with `AUK` (Section 5).
5. Register with the server using OPAQUE and `OPW` (Section 4).
6. Upload the email address, `salt`, Argon2id parameters, OPAQUE registration record, wrapped key set and public keys.
7. Store `sk` in the platform's secure storage (Keychain, Android Keystore, or the operating system credential store).
8. Show the Emergency Kit (3.7). The client MUST NOT finish onboarding until the user confirms they have saved it, for example by typing one group of the Secret Key back.

The client MUST NOT upload the master password, `sk`, `pw`, `AUK` or `OPW`.

## 3.7 Emergency Kit

The Emergency Kit is a one-page PDF, generated entirely on the device, containing:

- the account email address,
- the server address,
- the Secret Key, as text and as a QR code,
- an empty box where the user may write their master password.

The client MUST NOT upload the Emergency Kit or send it through any network print or conversion service.

## 3.8 Signing in on a new device

1. The user enters their email address, master password and Secret Key (or scans the Secret Key from another signed-in device; Section 10).
2. The client requests `salt` and the Argon2id parameters from the server.
3. The client validates the parameters (3.4) **before** running Argon2id.
4. The client derives `AUK` and `OPW` and logs in with OPAQUE.
5. The client fetches the wrapped account key set and decrypts it with `AUK`. Authentication failure here means a wrong password, a wrong Secret Key, or a tampered server response; the client MUST treat all three the same way.

To avoid revealing which email addresses have accounts, the server MUST answer requests for unknown addresses with a salt and parameters that look like a real account's (see RFC 9807, Section 10.9):

```
fake_salt = first 16 bytes of HMAC-SHA-256(fake_salt_key, "BlackBoxus v1 fake-salt" ‖ client_identity)
```

with the default Argon2id parameters. `fake_salt_key` is a 32-byte server secret, and `client_identity` is the canonical email address (Section 4.3). The same address always receives the same answer.

## 3.9 Security considerations

- **Server breach.** The server holds only `salt`, parameters, an OPAQUE record and ciphertext. Without `sk`, an attacker must guess 128 random bits as well as the password, which is infeasible.
- **Device theft.** A stolen device may hold `sk`. The master password and Argon2id then remain the protection, so the 12-character minimum and breach screening matter.
- **Parameter attacks.** Section 3.4's bounds prevent both downgrade and resource-exhaustion attacks by a malicious server.
- **Wrong salt from the server.** A different salt only produces wrong keys, which fail to decrypt the key set. It cannot cause any secret to leave the client.
- **No recovery by the provider.** If a user loses both their master password and every copy of their Secret Key, and has no signed-in device or recovery contact, the data cannot be recovered. This is inherent to the design and MUST be explained during onboarding.

## 3.10 Test vectors

Test vectors are in [`vectors/03-account-creation.json`](vectors/03-account-creation.json). They were generated by `vault-core` and checked against an independent implementation built from Python's `argon2-cffi` and the standard library's HMAC.
