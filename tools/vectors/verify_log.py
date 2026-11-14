"""Independent check of docs/spec/vectors/08-revision-log.json.

Rebuilds the two log entries of spec section 8 from their fields, verifies
both hybrid signatures with OpenSSL (through the `cryptography` package) and
recomputes the hash chain, sharing no code with vault-core.

    pip install cryptography
    python tools/vectors/verify_log.py docs/spec/vectors/08-revision-log.json
"""
import hashlib, json, struct, sys

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

v = json.load(open(sys.argv[1], encoding="utf-8"))
h = lambda k: bytes.fromhex(v[k])
results = {}
ctx = b"BlackBoxus v1 log-entry"


def header(seq, prev, ts, op):
    return (struct.pack(">H", 1) + h("vault_id_hex") + struct.pack(">Q", seq) + prev
            + h("author_account_id_hex") + struct.pack(">IQB", 1, ts, op))


def verify(signed, unsigned):
    sig = signed[len(unsigned):]
    ed25519.Ed25519PublicKey.from_public_bytes(h("author_ed25519_public_key_hex")).verify(
        sig[:64], bytes([len(ctx)]) + ctx + unsigned)
    mldsa.MLDSA65PublicKey.from_public_bytes(h("author_ml_dsa_public_key_hex")).verify(sig[64:], unsigned, ctx)
    return signed[:len(unsigned)] == unsigned and len(sig) == 3373


entry_hash = lambda signed: hashlib.sha256(b"BlackBoxus v1 log-entry-hash" + signed).digest()

# Entry 0: create vault, pinning the author's bundle.
bundle_hash = hashlib.sha256(h("author_signed_bundle_hex")).digest()
e0 = header(0, b"\0" * 32, v["entry0_timestamp_ms"], 1) + bundle_hash
results["Entry 0 encoding"] = e0 == h("entry0_unsigned_hex")
s0 = h("entry0_signed_sample_hex")
results["Entry 0 signature"] = verify(s0, e0)

# Entry 1: put item, chained to entry 0.
e1 = (header(1, entry_hash(s0), v["entry1_timestamp_ms"], 2)
      + h("item_id_hex") + struct.pack(">QI", 1, 1) + h("envelope_hash_hex"))
results["Entry 1 encoding and chain"] = e1 == h("entry1_unsigned_hex")
s1 = h("entry1_signed_sample_hex")
results["Entry 1 signature"] = verify(s1, e1)
results["Head"] = v["head_seq"] == 1 and entry_hash(s1) == h("head_hash_hex")

for name, ok in results.items():
    print(("OK  " if ok else "FAIL"), name)
sys.exit(0 if all(results.values()) else 1)
