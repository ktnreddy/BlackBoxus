// Keeps the pairing in IndexedDB. The key is a non-extractable CryptoKey,
// stored as the browser's own object: the bytes are never handed to
// JavaScript again.

export interface Paired {
  id: Uint8Array;
  key: CryptoKey;
}

const DB = "blackboxus";
const STORE = "pairing";

function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run<T>(mode: IDBTransactionMode, op: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const conn = await db();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = op(conn.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } finally {
    conn.close();
  }
}

export async function loadPairing(): Promise<Paired | null> {
  const value = (await run("readonly", (s) => s.get("current"))) as Paired | undefined;
  return value && value.key instanceof CryptoKey ? value : null;
}

export async function savePairing(p: Paired): Promise<void> {
  await run("readwrite", (s) => s.put(p, "current"));
}

export async function forgetPairing(): Promise<void> {
  await run("readwrite", (s) => s.delete("current"));
}
