// Checks the extension's crypto against the shared vectors in
// docs/spec/vectors/14-browser.json, which Rust and Python check too.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { b64, unb64, utf8 } from "./codec.js";
import { derivePairing, importKey, open, seal, sharedSecret } from "./crypto.js";

const v = JSON.parse(
  readFileSync(new URL("../../../docs/spec/vectors/14-browser.json", import.meta.url), "utf8"),
) as Record<string, string>;
const hex = (name: string) => Uint8Array.from(Buffer.from(v[name] ?? "", "hex"));

/** A P-256 private key from its scalar, as Web Crypto needs it. */
async function privateKey(scalarHex: string, publicKey: Uint8Array): Promise<CryptoKey> {
  const url = (bytes: Uint8Array) => b64(bytes);
  return crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      d: url(Uint8Array.from(Buffer.from(scalarHex, "hex"))),
      x: url(publicKey.slice(1, 33)),
      y: url(publicKey.slice(33, 65)),
    },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
}

test("pairing and sealing match the vectors", async () => {
  const extPub = hex("extension_public_hex");
  const appPub = hex("app_public_hex");
  const ext = await privateKey(v.extension_private_hex ?? "", extPub);
  const shared = await sharedSecret(ext, appPub);
  assert.deepEqual(shared, hex("shared_hex"));

  const id = hex("id_hex");
  const { keyBytes, code } = await derivePairing(id, extPub, appPub, shared);
  assert.deepEqual(keyBytes, hex("key_hex"));
  assert.equal(code, v.code);

  const key = await importKey(keyBytes);
  const request = await seal(key, id, "request", utf8(v.request_plaintext ?? ""), hex("request_nonce_hex"));
  assert.deepEqual(request.sealed, hex("request_sealed_hex"));
  const response = await open(key, id, "response", hex("response_nonce_hex"), hex("response_sealed_hex"));
  assert.equal(new TextDecoder().decode(response), v.response_plaintext);

  // Wrong direction or ID does not open.
  await assert.rejects(open(key, id, "request", hex("response_nonce_hex"), hex("response_sealed_hex")));
  await assert.rejects(open(key, new Uint8Array(16), "response", hex("response_nonce_hex"), hex("response_sealed_hex")));
});

test("base64url round trips and rejects other alphabets", () => {
  const bytes = Uint8Array.from([0, 251, 255, 1, 2]);
  assert.equal(b64(bytes), "APv_AQI");
  assert.deepEqual(unb64("APv_AQI"), bytes);
  assert.throws(() => unb64("AP+/AQI"));
});
