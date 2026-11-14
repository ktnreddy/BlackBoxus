"""Independent check of docs/spec/vectors/09-key-transparency.json.

Implements RFC 9162 Merkle tree hashing and proof verification, and the
BlackBoxus fingerprint, with Python's standard library; verifies the signed
tree head with OpenSSL (through the `cryptography` package). Shares no code
with BlackBoxus.

    pip install cryptography
    python tools/vectors/verify_key_transparency.py docs/spec/vectors/09-key-transparency.json
"""
import hashlib, json, struct, sys

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

v = json.load(open(sys.argv[1], encoding="utf-8"))
H = lambda b: hashlib.sha256(b).digest()
unhex = lambda xs: [bytes.fromhex(x) for x in xs]
results = {}


def mth(leaves):
    n = len(leaves)
    if n == 0:
        return H(b"")
    if n == 1:
        return H(b"\x00" + leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return H(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))


def verify_inclusion(index, size, leaf_hash, proof, root):
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf_hash
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = H(b"\x01" + p + r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = H(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first, second, root1, root2, proof):
    if first == second:
        return not proof and root1 == root2
    path = ([root1] if first & (first - 1) == 0 else []) + proof
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = H(b"\x01" + c + fr), H(b"\x01" + c + sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = H(b"\x01" + sr + c)
        fn >>= 1
        sn >>= 1
    return fr == root1 and sr == root2 and sn == 0


leaves = unhex(v["leaves_hex"])
roots = unhex(v["roots_by_size_hex"])
results["Roots for every size"] = all(mth(leaves[:n]) == roots[n] for n in range(len(roots)))
results["Leaf encoding"] = all(
    l == struct.pack(">H", 1) + bytes([i + 1]) * 16 + struct.pack(">I", 1)
    + bytes((i * 32 + j) % 256 for j in range(32)) + struct.pack(">Q", 1762000000000 + i)
    for i, l in enumerate(leaves))

inc = v["inclusion"]
results["Inclusion proof"] = verify_inclusion(
    inc["leaf_index"], inc["tree_size"], H(b"\x00" + leaves[inc["leaf_index"]]),
    unhex(inc["proof_hex"]), roots[inc["tree_size"]])
con = v["consistency"]
results["Consistency proof"] = verify_consistency(
    con["first_size"], con["second_size"], roots[con["first_size"]], roots[con["second_size"]],
    unhex(con["proof_hex"]))

sth = bytes.fromhex(v["signed_tree_head_sample_hex"])
unsigned, sig = sth[:50], sth[50:]
ctx = b"BlackBoxus v1 tree-head"
try:
    ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["log_ed25519_public_key_hex"])).verify(
        sig[:64], bytes([len(ctx)]) + ctx + unsigned)
    mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(v["log_ml_dsa_public_key_hex"])).verify(sig[64:], unsigned, ctx)
    version, size = struct.unpack(">HQ", unsigned[:10])
    results["Signed tree head"] = version == 1 and size == 7 and unsigned[10:42] == roots[7]
except Exception as e:
    print("signature error:", type(e).__name__, e)
    results["Signed tree head"] = False

d = hashlib.sha512(b"BlackBoxus v1 fingerprint" + bytes.fromhex(v["fingerprint_account_id_hex"])
                   + H(bytes.fromhex(v["fingerprint_signed_bundle_hex"]))).digest()
fp = " ".join(f"{int.from_bytes(d[i * 5:i * 5 + 5], 'big') % 100000:05d}" for i in range(6))
results["Fingerprint"] = fp == v["fingerprint"]

for name, ok in results.items():
    print(("OK  " if ok else "FAIL"), name)
sys.exit(0 if all(results.values()) else 1)
