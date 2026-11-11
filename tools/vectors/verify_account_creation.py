"""Independent check of docs/spec/vectors/03-account-creation.json.

Implements spec section 3 with Python's standard library and argon2-cffi,
sharing no code with vault-core.

    pip install argon2-cffi
    python tools/vectors/verify_account_creation.py docs/spec/vectors/03-account-creation.json
"""
import hashlib, hmac, json, sys, unicodedata
from argon2.low_level import hash_secret_raw, Type

def hkdf(salt, ikm, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:n]

A = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
def display(sk):
    n = int.from_bytes(sk, "big")
    digits = [(n >> s) & 31 for s in range(125, -1, -5)]
    h = hashlib.sha256(b"BlackBoxus v1 secret-key checksum" + sk).digest()
    ten = (h[0] << 2) | (h[1] >> 6)
    digits += [ten >> 5, ten & 31]
    s = "".join(A[d] for d in digits)
    return "B1-" + "-".join(s[i:i+7] for i in range(0, 28, 7))

v = json.load(open(sys.argv[1], encoding="utf-8"))
ok = True
for c in v["kdf"]:
    p = unicodedata.normalize("NFKC", c["password"]).encode()
    assert p.hex() == c["password_nfkc_hex"], c["description"]
    sk, salt = bytes.fromhex(c["secret_key_hex"]), bytes.fromhex(c["salt_hex"])
    pw = hash_secret_raw(p, salt, time_cost=c["iterations"], memory_cost=c["memory_kib"],
                         parallelism=c["parallelism"], hash_len=32, type=Type.ID, version=19)
    auk = hkdf(salt, pw + sk, b"BlackBoxus v1 account-unlock-key")
    opw = hkdf(salt, pw + sk, b"BlackBoxus v1 opaque-password")
    good = auk.hex() == c["account_unlock_key_hex"] and opw.hex() == c["opaque_password_hex"]
    ok &= good
    print(("OK  " if good else "FAIL"), c["description"])
for c in v["secret_key_display"]:
    good = display(bytes.fromhex(c["secret_key_hex"])) == c["display"]
    ok &= good
    print(("OK  " if good else "FAIL"), "display", c["secret_key_hex"])
sys.exit(0 if ok else 1)
