// The extension's service worker: pairs with the app, asks it for logins,
// and fills them when the user asks. It keeps no passwords: each one is
// requested at the moment of filling and dropped straight after.

import { b64, unb64, utf8 } from "./codec.js";
import { derivePairing, ephemeralKey, importKey, open, seal, sharedSecret } from "./crypto.js";
import { fillLogin, type FillResult } from "./fill.js";
import { AppUnavailable, Connection } from "./native.js";
import { forgetPairing, loadPairing, savePairing, type Paired } from "./store.js";

/** A login offered for the current page. Carries no secrets. */
export interface LoginChoice {
  vault: string;
  vault_name: string;
  item: string;
  title: string;
  username: string;
}

/** What the popup should show. */
export type View =
  | { view: "unpaired"; pairing: PairingState | null }
  | { view: "app_closed" | "disabled" | "locked" | "no_account" }
  | { view: "no_page" }
  | { view: "logins"; site: string; insecure: boolean; logins: LoginChoice[] }
  | { view: "error"; message: string };

export interface PairingState {
  code: string | null;
  status: "starting" | "waiting" | "paired" | "denied" | "failed";
}

let pairing: PairingState | null = null;

/** Sends one sealed request and returns the app's answer. */
async function ask(conn: Connection, p: Paired, body: object): Promise<Record<string, unknown>> {
  const { nonce, sealed } = await seal(p.key, p.id, "request", utf8(JSON.stringify(body)));
  conn.send({ t: "req", id: b64(p.id), n: b64(nonce), c: b64(sealed) });
  const reply = await conn.next(15_000);
  if (reply.t === "error") throw new AppUnavailable(reply.code);
  if (reply.t !== "res") throw new AppUnavailable("malformed");
  const plain = await open(p.key, p.id, "response", unb64(reply.n), unb64(reply.c));
  return JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
}

/** Runs `job` with a connection and the pairing, turning failures into a view. */
async function withApp(job: (conn: Connection, p: Paired) => Promise<View>): Promise<View> {
  const p = await loadPairing();
  if (!p) return { view: "unpaired", pairing };
  const conn = new Connection();
  try {
    return await job(conn, p);
  } catch (e) {
    if (e instanceof AppUnavailable) {
      switch (e.code) {
        case "unpaired":
          // The app forgot this browser (removed in Settings, or turned off).
          await forgetPairing();
          return { view: "unpaired", pairing: null };
        case "disabled":
          return { view: "disabled" };
        case "app_closed":
        case "not_installed":
        case "timeout":
          return { view: "app_closed" };
      }
    }
    return { view: "error", message: "Something went wrong. Try again." };
  } finally {
    conn.close();
  }
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function webPage(url: string | undefined): URL | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u : null;
  } catch {
    return null;
  }
}

async function state(): Promise<View> {
  const tab = await activeTab();
  return withApp(async (conn, p) => {
    const status = await ask(conn, p, { op: "status" });
    if (!status.account) return { view: "no_account" };
    if (!status.unlocked) return { view: "locked" };
    const page = webPage(tab?.url);
    if (!page) return { view: "no_page" };
    const answer = await ask(conn, p, { op: "logins", url: page.href });
    if (answer.error === "locked") return { view: "locked" };
    return {
      view: "logins",
      site: page.hostname,
      insecure: page.protocol === "http:",
      logins: (answer.logins as LoginChoice[] | undefined) ?? [],
    };
  });
}

function browserName(): string {
  const brands = (navigator as Navigator & { userAgentData?: { brands: { brand: string }[] } })
    .userAgentData?.brands.map((b) => b.brand) ?? [];
  if (brands.includes("Microsoft Edge")) return "Microsoft Edge";
  if (brands.includes("Brave")) return "Brave";
  if (brands.includes("Google Chrome")) return "Google Chrome";
  return "Chromium";
}

/** Starts pairing. Resolves once the code is known; the user then approves
 *  in the app, and `pairing.status` follows. */
async function pair(): Promise<PairingState> {
  if (pairing && (pairing.status === "starting" || pairing.status === "waiting")) return pairing;
  pairing = { code: null, status: "starting" };
  const current = pairing;
  const conn = new Connection();
  try {
    const id = crypto.getRandomValues(new Uint8Array(16));
    const mine = await ephemeralKey();
    conn.send({ t: "pair", id: b64(id), key: b64(mine.public), browser: browserName() });
    const offer = await conn.next(10_000);
    if (offer.t !== "pair") throw new AppUnavailable(offer.t === "error" ? offer.code : "malformed");
    const appKey = unb64(offer.key);
    const shared = await sharedSecret(mine.pair.privateKey, Uint8Array.from(appKey));
    const { keyBytes, code } = await derivePairing(id, mine.public, appKey, shared);
    const key = await importKey(keyBytes);
    keyBytes.fill(0);
    current.code = code;
    current.status = "waiting";
    // The user has two minutes to check the code and allow it in the app.
    void conn
      .next(125_000)
      .then(async (answer) => {
        if (answer.t === "paired") {
          await savePairing({ id, key });
          current.status = "paired";
        } else {
          current.status = "denied";
        }
      })
      .catch(() => (current.status = "failed"))
      .finally(() => conn.close());
  } catch (e) {
    conn.close();
    current.status = e instanceof AppUnavailable && e.code === "disabled" ? "denied" : "failed";
  }
  return current;
}

/** Fills one login into the active tab. */
async function fill(vault: string, item: string): Promise<"filled" | "failed" | View> {
  const tab = await activeTab();
  const page = webPage(tab?.url);
  if (!tab?.id || !page) return "failed";
  const tabId = tab.id;
  const outcome: { result: FillResult | "failed" } = { result: "failed" };
  const view = await withApp(async (conn, p) => {
    const answer = await ask(conn, p, { op: "fill", url: page.href, vault, item });
    if (answer.error === "locked") return { view: "locked" };
    if (typeof answer.origin !== "string") return { view: "error", message: "That login isn't for this site." };
    const [injected] = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: fillLogin,
      args: [
        answer.origin,
        String(answer.username ?? ""),
        String(answer.password ?? ""),
        typeof answer.totp === "string" ? answer.totp : null,
      ],
    });
    outcome.result = (injected?.result as FillResult | undefined) ?? "failed";
    return { view: "no_page" };
  });
  if (outcome.result === "filled") return "filled";
  if (view.view === "no_page") return "failed";
  return view;
}

/** The keyboard shortcut: fill the only login for the page, or show the choices. */
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const view = await state();
  if (view.view === "logins" && view.logins.length === 1 && view.logins[0]) {
    const only = view.logins[0];
    if ((await fill(only.vault, only.item)) === "filled") return;
  }
  await chrome.action.openPopup().catch(() => {});
});

chrome.runtime.onMessage.addListener((message: { cmd?: string; vault?: string; item?: string }, sender, reply) => {
  // Only the extension's own popup may ask; never a page or another extension.
  if (sender.id !== chrome.runtime.id || sender.tab) return false;
  const work: Promise<unknown> | null =
    message.cmd === "state"
      ? state()
      : message.cmd === "pair"
        ? pair()
        : message.cmd === "pairing"
          ? Promise.resolve(pairing)
          : message.cmd === "fill" && message.vault && message.item
            ? fill(message.vault, message.item)
            : null;
  if (!work) return false;
  work.then(reply, () => reply({ view: "error", message: "Something went wrong. Try again." }));
  return true;
});
