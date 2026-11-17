"""Independent check of docs/spec/vectors/14-browser.json.

Recomputes the browser pairing exchange and sealing of spec section 14 with
OpenSSL (through the `cryptography` package). Shares no code with the app
or the extension.

    pip install cryptography
    python tools/vectors/verify_browser.py docs/spec/vectors/14-browser.json
    python tools/vectors/verify_browser.py --generate   # print new vectors
"""
import hashlib, json, sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PAIR = b"BlackBoxus v1 browser-pair"
REQUEST = b"BlackBoxus v1 browser-request"
RESPONSE = b"BlackBoxus v1 browser-response"
RAW = serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint


def compute(v):
    ext = ec.derive_private_key(int(v["extension_private_hex"], 16), ec.SECP256R1())
    app = ec.derive_private_key(int(v["app_private_hex"], 16), ec.SECP256R1())
    ext_pub, app_pub = ext.public_key().public_bytes(*RAW), app.public_key().public_bytes(*RAW)
    pid = bytes.fromhex(v["id_hex"])
    shared = ext.exchange(ec.ECDH(), app.public_key())
    assert shared == app.exchange(ec.ECDH(), ext.public_key())
    transcript = hashlib.sha256(PAIR + pid + ext_pub + app_pub).digest()
    okm = HKDF(hashes.SHA256(), 36, transcript, PAIR).derive(shared)
    key, code = okm[:32], int.from_bytes(okm[32:], "big") % 1_000_000
    nonce = bytes.fromhex(v["request_nonce_hex"])
    sealed = AESGCM(key).encrypt(nonce, v["request_plaintext"].encode(), REQUEST + pid)
    rnonce = bytes.fromhex(v["response_nonce_hex"])
    rsealed = AESGCM(key).encrypt(rnonce, v["response_plaintext"].encode(), RESPONSE + pid)
    return {
        "extension_public_hex": ext_pub.hex(),
        "app_public_hex": app_pub.hex(),
        "shared_hex": shared.hex(),
        "key_hex": key.hex(),
        "code": f"{code:06d}",
        "request_sealed_hex": sealed.hex(),
        "response_sealed_hex": rsealed.hex(),
    }


if sys.argv[1:] == ["--generate"]:
    v = {
        "id_hex": bytes(range(0x10, 0x20)).hex(),
        "extension_private_hex": hashlib.sha256(b"extension").hexdigest(),
        "app_private_hex": hashlib.sha256(b"app").hexdigest(),
        "request_nonce_hex": bytes(range(12)).hex(),
        "request_plaintext": '{"op":"logins","url":"https://www.example.com/login"}',
        "response_nonce_hex": bytes(range(12, 24)).hex(),
        "response_plaintext": '{"logins":[]}',
    }
    v.update(compute(v))
    print(json.dumps(v, indent=2))
    sys.exit(0)

v = json.load(open(sys.argv[1], encoding="utf-8"))
got = compute(v)
ok = True
for name, value in got.items():
    good = value == v[name]
    ok &= good
    print(("OK   " if good else "FAIL ") + name)
sys.exit(0 if ok else 1)
