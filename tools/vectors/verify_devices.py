"""Independent check of docs/spec/vectors/10-devices.json.

Recomputes the QR text, the encrypted enrolment transfer and the passkey
wrapping key of spec section 10 with the standard library and libsodium
(through PyNaCl), sharing no code with vault-core.

    pip install pynacl
    python tools/vectors/verify_devices.py docs/spec/vectors/10-devices.json
"""
import hashlib, hmac, json, struct, sys

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

v = json.load(open(sys.argv[1], encoding="utf-8"))
h = lambda k: bytes.fromhex(v[k])
results = {}


def hkdf(salt, ikm, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


sid, secret = h("session_id_hex"), h("enrolment_secret_hex")
results["QR text"] = v["qr_text"] == "blackboxus-enrol:1:" + (sid + secret).hex()

label = b"BlackBoxus v1 enrolment"
key = hkdf(b"", secret, label + sid)
email, server = v["email"].encode(), v["server"].encode()
plaintext = (struct.pack(">H", 1) + h("account_id_hex") + h("secret_key_hex")
             + bytes([len(email)]) + email + bytes([len(server)]) + server + struct.pack(">H", 0))
sealed = h("nonce_hex") + crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, label + sid, h("nonce_hex"), key)
results["Enrolment transfer"] = sealed == h("sealed_hex")

results["Passkey PRF input"] = hashlib.sha256(b"BlackBoxus v1 passkey-prf-input" + h("account_id_hex")).digest() == h("prf_input_hex")
results["Passkey wrapping key"] = hkdf(hashlib.sha256(h("credential_id_hex")).digest(), h("prf_output_hex"),
                                       b"BlackBoxus v1 passkey-unlock") == h("passkey_wrapping_key_hex")

for name, ok in results.items():
    print(("OK  " if ok else "FAIL"), name)
sys.exit(0 if all(results.values()) else 1)
