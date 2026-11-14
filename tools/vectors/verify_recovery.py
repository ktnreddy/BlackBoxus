"""Independent check of docs/spec/vectors/11-recovery.json.

Recomputes the recovery-key display format and derived values of spec
section 11 with the standard library, and opens the sample emergency grant
with OpenSSL (through the `cryptography` package: ML-KEM-768, X25519, Ed25519,
ML-DSA-65) and libsodium (through PyNaCl). Shares no code with vault-core.

    pip install cryptography pynacl
    python tools/vectors/verify_recovery.py docs/spec/vectors/11-recovery.json
"""
import hashlib, hmac, json, struct, sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

v = json.load(open(sys.argv[1], encoding="utf-8"))
h = lambda k: bytes.fromhex(v[k])
A = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
results = {}


def hkdf(salt, ikm, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


key = h("recovery_key_hex")
n = int.from_bytes(key, "big")  # 256 bits; 4 zero padding bits in front make 260
digits = [(n >> s) & 31 for s in range(255, -1, -5)]
c = hashlib.sha256(b"BlackBoxus v1 recovery-key checksum" + key).digest()
ten = (c[0] << 2) | (c[1] >> 6)
digits += [ten >> 5, ten & 31]
s = "".join(A[d] for d in digits)
display = "BR1-" + "-".join(s[i:i + 6] for i in range(0, 54, 6))
results["Display format"] = len(digits) == 54 and display == v["recovery_key_display"]

acct = h("account_id_hex")
results["Wrapping key"] = hkdf(acct, key, b"BlackBoxus v1 recovery-wrap") == h("wrapping_key_hex")
token = hkdf(acct, key, b"BlackBoxus v1 recovery-auth")
results["Auth token"] = token == h("auth_token_hex")
results["Auth verifier"] = hashlib.sha256(token).digest() == h("auth_verifier_hex")

# Emergency grant (spec section 11.4).
grant = h("grant_sample_hex")
raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
header, enc, sealed, sig = grant[:44], grant[44:1164], grant[1164:1236], grant[1236:]
version, = struct.unpack(">H", header[:2])
results["Grant header"] = (version == 1 and len(grant) == 4609 and header[2:18] == acct
                           and header[22:38] == h("contact_account_id_hex")
                           and struct.unpack(">H", header[42:44])[0] == 7)
ctx = b"BlackBoxus v1 emergency-grant"
try:
    ed25519.Ed25519PublicKey.from_public_bytes(h("owner_ed25519_public_key_hex")).verify(
        sig[:64], bytes([len(ctx)]) + ctx + grant[:1236])
    mldsa.MLDSA65PublicKey.from_public_bytes(h("owner_ml_dsa_public_key_hex")).verify(sig[64:], grant[:1236], ctx)
    results["Owner signature"] = True
except Exception as e:
    print("signature error:", type(e).__name__, e)
    results["Owner signature"] = False

expanded = hashlib.shake_256(h("contact_xwing_seed_hex")).digest(96)
ml_sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64])
x_sk = x25519.X25519PrivateKey.from_private_bytes(expanded[64:])
pk_x = x_sk.public_key().public_bytes(*raw)
recipient_pk = ml_sk.public_key().public_bytes(*raw) + pk_x
ct_m, ct_x = enc[:1088], enc[1088:]
ss = hashlib.sha3_256(ml_sk.decapsulate(ct_m) + x_sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
                      + ct_x + pk_x + b"\\.//^\\").digest()
wrap = hkdf(hashlib.sha256(recipient_pk).digest(), ss, ctx + header + enc)
ek = crypto_aead_xchacha20poly1305_ietf_decrypt(sealed[24:], header, sealed[:24], wrap)
results["Grant decrypts to the emergency key"] = ek == h("grant_emergency_key_hex")

for name, ok in results.items():
    print(("OK  " if ok else "FAIL"), name)
sys.exit(0 if all(results.values()) else 1)
