"""Independent check of docs/spec/vectors/06-items.json.

Rebuilds the item envelope of spec section 6 from the item's fields with the
standard library and libsodium (through PyNaCl), sharing no code with
vault-core.

    pip install pynacl
    python tools/vectors/verify_items.py docs/spec/vectors/06-items.json
"""
import json, struct, sys

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768]

v = json.load(open(sys.argv[1], encoding="utf-8"))
h = lambda k: bytes.fromhex(v[k])
item = v["item"]

content = struct.pack(">BBQQH", 1, item["item_type"], item["created_ms"], item["modified_ms"], len(item["fields"]))
for f in item["fields"]:
    label, value = f["label"].encode(), f["value"].encode()
    content += struct.pack(">BH", f["kind"], len(label)) + label + struct.pack(">I", len(value)) + value

bucket = next(b for b in BUCKETS if b >= len(content) + 1)
padded = content + b"\x80" + b"\x00" * (bucket - len(content) - 1)

vault_id, item_id, rev = h("vault_id_hex"), h("item_id_hex"), v["revision"]
tail = struct.pack(">H", 1) + vault_id + item_id + struct.pack(">Q", rev)
wrapped = h("key_nonce_hex") + crypto_aead_xchacha20poly1305_ietf_encrypt(
    h("item_key_hex"), b"BlackBoxus v1 item-key" + tail, h("key_nonce_hex"), h("vault_key_hex"))
sealed = h("content_nonce_hex") + crypto_aead_xchacha20poly1305_ietf_encrypt(
    padded, b"BlackBoxus v1 item" + tail, h("content_nonce_hex"), h("item_key_hex"))
envelope = tail + wrapped + sealed

results = {
    "Envelope bytes": envelope == h("envelope_hex"),
    "Envelope length": len(envelope) == len(h("envelope_hex")),
}
# Also decrypt the published envelope the other way round.
pub = h("envelope_hex")
item_key = crypto_aead_xchacha20poly1305_ietf_decrypt(pub[42 + 24:42 + 72], b"BlackBoxus v1 item-key" + tail, pub[42:42 + 24], h("vault_key_hex"))
plain = crypto_aead_xchacha20poly1305_ietf_decrypt(pub[42 + 72 + 24:], b"BlackBoxus v1 item" + tail, pub[42 + 72:42 + 72 + 24], item_key)
results["Decrypts to the same content"] = plain == padded

for name, ok in results.items():
    print(("OK  " if ok else "FAIL"), name)
sys.exit(0 if all(results.values()) else 1)
