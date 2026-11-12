"""Independent check of docs/spec/vectors/04-login.json.

Implements the BlackBoxus-specific parts of spec section 4 (identity
canonicalisation and session-token derivation) with Python's standard
library only, sharing no code with vault-core.

    python tools/vectors/verify_login.py docs/spec/vectors/04-login.json
"""
import hashlib, hmac, json, re, sys, unicodedata


def client_identity(email):
    c = unicodedata.normalize("NFKC", email.strip()).lower()
    parts = c.split("@")
    ok = (len(c.encode()) <= 254 and len(parts) == 2 and all(parts)
          and not any(ch.isspace() for ch in c))
    return c if ok else None


ORIGIN = re.compile(r"^(https|http)://([a-z0-9.\-]+)(:[0-9]+)?$")


def server_identity(origin):
    o = origin.strip().lower()
    m = ORIGIN.match(o) if o.isascii() and len(o) <= 255 else None
    if not m:
        return None
    scheme, host = m.group(1), m.group(2)
    if scheme == "http" and host not in ("localhost", "127.0.0.1"):
        return None
    return o


def session_token(session_key):
    prk = hmac.new(b"", session_key, hashlib.sha256).digest()
    return hmac.new(prk, b"BlackBoxus v1 session-token" + b"\x01", hashlib.sha256).digest()


v = json.load(open(sys.argv[1], encoding="utf-8"))
results = []
results += [client_identity(c["input"]) == c["canonical"] for c in v["client_identity"]]
results += [client_identity(c) is None for c in v["client_identity_invalid"]]
results += [server_identity(c["input"]) == c["canonical"] for c in v["server_identity"]]
results += [server_identity(c) is None for c in v["server_identity_invalid"]]
for c in v["session_token"]:
    t = session_token(bytes.fromhex(c["session_key_hex"]))
    results.append(t.hex() == c["session_token_hex"])
    results.append(hashlib.sha256(t).hexdigest() == c["storage_hash_hex"])
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
