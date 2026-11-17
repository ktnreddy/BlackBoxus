// The pairing exchange and message sealing of spec section 14, with the
// browser's Web Crypto API. The shared key is imported as non-extractable,
// so not even this extension's own code can read it back.

import { concat, utf8 } from "./codec.js";

const PAIR = utf8("BlackBoxus v1 browser-pair");
const REQUEST = utf8("BlackBoxus v1 browser-request");
const RESPONSE = utf8("BlackBoxus v1 browser-response");

export type Direction = "request" | "response";

/** A fresh P-256 key pair for one pairing, and its public key as bytes. */
export async function ephemeralKey(): Promise<{ pair: CryptoKeyPair; public: Uint8Array }> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { pair, public: raw };
}

/** The raw shared secret with the app's public key. */
export async function sharedSecret(mine: CryptoKey, theirs: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", theirs, { name: "ECDH", namedCurve: "P-256" }, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: key }, mine, 256));
}

/** The pairing key's bytes and the six-digit code both sides show. */
export async function derivePairing(
  id: Uint8Array,
  extensionKey: Uint8Array,
  appKey: Uint8Array,
  shared: Uint8Array,
): Promise<{ keyBytes: Uint8Array; code: string }> {
  const transcript = new Uint8Array(
    await crypto.subtle.digest("SHA-256", concat(PAIR, id, extensionKey, appKey)),
  );
  const ikm = await crypto.subtle.importKey("raw", concat(shared), "HKDF", false, ["deriveBits"]);
  const okm = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: transcript, info: PAIR },
      ikm,
      36 * 8,
    ),
  );
  const view = new DataView(okm.buffer, 32, 4);
  const code = (view.getUint32(0) % 1_000_000).toString().padStart(6, "0");
  return { keyBytes: okm.slice(0, 32), code };
}

/** Imports the pairing key so it can only seal and open. */
export function importKey(bytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", concat(bytes), "AES-GCM", false, ["encrypt", "decrypt"]);
}

function aad(id: Uint8Array, direction: Direction): Uint8Array<ArrayBuffer> {
  return concat(direction === "request" ? REQUEST : RESPONSE, id);
}

export async function seal(
  key: CryptoKey,
  id: Uint8Array,
  direction: Direction,
  plaintext: Uint8Array,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(12)),
): Promise<{ nonce: Uint8Array; sealed: Uint8Array }> {
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: concat(nonce), additionalData: aad(id, direction) },
    key,
    concat(plaintext),
  );
  return { nonce, sealed: new Uint8Array(sealed) };
}

export async function open(
  key: CryptoKey,
  id: Uint8Array,
  direction: Direction,
  nonce: Uint8Array,
  sealed: Uint8Array,
): Promise<Uint8Array> {
  if (nonce.length !== 12) throw new Error("bad nonce");
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: concat(nonce), additionalData: aad(id, direction) },
      key,
      concat(sealed),
    ),
  );
}
