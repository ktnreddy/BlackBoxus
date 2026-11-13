"""Independent check of docs/spec/vectors/07-vaults-and-sharing.json.

Re-derives spec section 7 with OpenSSL (through the `cryptography` package:
ML-KEM-768 decapsulation, X25519, Ed25519, ML-DSA-65) and libsodium (through
PyNaCl: XChaCha20-Poly1305), sharing no code with vault-core.

    pip install cryptography pynacl
    python tools/vectors/verify_vaults.py docs/spec/vectors/07-vaults-and-sharing.json
"""
import hashlib, hmac, json, struct, sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

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


# 7.3 Owner wrapping.
vault_id, version = h("vault_id_hex"), v["vault_key_version"]
aad = b"BlackBoxus v1 vault-key" + struct.pack(">H", 1) + h("owner_account_id_hex") + vault_id + struct.pack(">I", version)
ct = crypto_aead_xchacha20poly1305_ietf_encrypt(h("vault_key_hex"), aad, h("owner_nonce_hex"), h("owner_account_key_hex"))
owner = struct.pack(">H", 1) + vault_id + struct.pack(">I", version) + h("owner_nonce_hex") + ct
results["Owner-wrapped vault key"] = owner == h("owner_wrapped_hex")

# 7.4 Share: header.
header = (struct.pack(">H", 1) + vault_id + struct.pack(">I", version)
          + h("sender_account_id_hex") + struct.pack(">I", v["sender_key_set_version"])
          + h("recipient_account_id_hex") + struct.pack(">I", v["recipient_key_set_version"]))
body = h("share_body_hex")
results["Share header"] = body[:62] == header
enc, sealed = body[62:62 + 1120], body[62 + 1120:]
ct_m, ct_x = enc[:1088], enc[1088:]

# X-Wing ephemeral key: ct_X = X25519(randomness[32:64], 9).
eph = x25519.X25519PrivateKey.from_private_bytes(h("kem_randomness_hex")[32:])
raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
results["X-Wing ephemeral key"] = eph.public_key().public_bytes(*raw) == ct_x

# X-Wing decapsulation by the recipient (draft section 5.4).
expanded = hashlib.shake_256(h("recipient_xwing_seed_hex")).digest(96)
ml_sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64])
x_sk = x25519.X25519PrivateKey.from_private_bytes(expanded[64:])
pk_x = x_sk.public_key().public_bytes(*raw)
recipient_pk = ml_sk.public_key().public_bytes(*raw) + pk_x
results["Recipient X-Wing public key"] = recipient_pk == h("recipient_xwing_public_key_hex")
ss_m = ml_sk.decapsulate(ct_m)
ss_x = x_sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
ss = hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + b"\\.//^\\").digest()

# Key derivation and decryption.
wrap_key = hkdf(hashlib.sha256(recipient_pk).digest(), ss, b"BlackBoxus v1 vault-share" + header + enc)
vault_key = crypto_aead_xchacha20poly1305_ietf_decrypt(sealed[24:], header, sealed[:24], wrap_key)
results["Share decrypts to the vault key"] = vault_key == h("vault_key_hex")
results["Share nonce"] = sealed[:24] == h("share_nonce_hex")

# Sender signature on the sample share.
share = h("share_sample_hex")
ctx = b"BlackBoxus v1 vault-share"
try:
    ed25519.Ed25519PublicKey.from_public_bytes(h("sender_ed25519_public_key_hex")).verify(
        share[len(body):len(body) + 64], bytes([len(ctx)]) + ctx + body)
    mldsa.MLDSA65PublicKey.from_public_bytes(h("sender_ml_dsa_public_key_hex")).verify(
        share[len(body) + 64:], body, ctx)
    results["Sender signature"] = share[:len(body)] == body and len(share) == 4627
except Exception as e:
    print("signature error:", type(e).__name__, e)
    results["Sender signature"] = False

for name, ok in results.items():
    print(("OK  " if ok else "FAIL"), name)
sys.exit(0 if all(results.values()) else 1)
