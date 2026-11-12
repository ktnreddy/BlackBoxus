"""Independent check of docs/spec/vectors/05-key-sets.json.

Recomputes spec section 5 with OpenSSL (through the `cryptography` package,
for ML-KEM-768, ML-DSA-65, X25519 and Ed25519) and libsodium (through PyNaCl,
for XChaCha20-Poly1305). It shares no code with vault-core.

    pip install cryptography pynacl
    python tools/vectors/verify_key_sets.py docs/spec/vectors/05-key-sets.json
"""
import hashlib, json, struct, sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw

v = json.load(open(sys.argv[1], encoding="utf-8"))
h = lambda k: bytes.fromhex(v[k])
results = {}

# X-Wing public key (draft-connolly-cfrg-xwing-kem, section 5.2).
expanded = hashlib.shake_256(h("xwing_seed_hex")).digest(96)
pk_m = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64]).public_key().public_bytes(*RAW)
pk_x = x25519.X25519PrivateKey.from_private_bytes(expanded[64:]).public_key().public_bytes(*RAW)
xwing_pk = pk_m + pk_x
results["X-Wing public key"] = xwing_pk == h("xwing_public_key_hex")

# Identity keys.
ed_pk = ed25519.Ed25519PrivateKey.from_private_bytes(h("ed25519_seed_hex")).public_key().public_bytes(*RAW)
ml_pk = mldsa.MLDSA65PrivateKey.from_seed_bytes(h("ml_dsa_seed_hex")).public_key().public_bytes(*RAW)
results["Ed25519 public key"] = ed_pk == h("ed25519_public_key_hex")
results["ML-DSA-65 public key"] = ml_pk == h("ml_dsa_public_key_hex")

# Public key bundle (section 5.5), unsigned part.
version, method = v["key_set_version"], v["method"]
account_id = h("account_id_hex")
bundle = struct.pack(">H", 1) + account_id + struct.pack(">I", version) + xwing_pk + ed_pk + ml_pk
results["Public key bundle"] = bundle == h("public_bundle_hex")

# Self-signature on a sample signed bundle (signatures are randomised, so this
# checks verification rather than fixed bytes).
signed = h("signed_public_bundle_sample_hex")
ctx = b"BlackBoxus v1 public-key-bundle"
sig = signed[len(bundle):]
try:
    ed25519.Ed25519PublicKey.from_public_bytes(ed_pk).verify(sig[:64], bytes([len(ctx)]) + ctx + bundle)
    mldsa.MLDSA65PublicKey.from_public_bytes(ml_pk).verify(sig[64:], bundle, ctx)
    results["Bundle self-signature"] = signed[:len(bundle)] == bundle and len(sig) == 64 + 3309
except Exception as e:
    print("signature error:", type(e).__name__, e)
    results["Bundle self-signature"] = False

# Wrapped key set (section 5.4).
plaintext = h("account_key_hex") + h("xwing_seed_hex") + h("ed25519_seed_hex") + h("ml_dsa_seed_hex")
aad = b"BlackBoxus v1 key-set" + struct.pack(">H", 1) + account_id + struct.pack(">IB", version, method)
ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, h("nonce_hex"), h("wrapping_key_hex"))
wrapped = struct.pack(">HIB", 1, version, method) + h("nonce_hex") + ct
results["Wrapped key set"] = wrapped == h("wrapped_hex")

for name, ok in results.items():
    print(("OK  " if ok else "FAIL"), name)
sys.exit(0 if all(results.values()) else 1)
