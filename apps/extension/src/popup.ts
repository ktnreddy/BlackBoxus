// The toolbar popup. Filling only ever starts from a click here (or the
// keyboard shortcut), in the browser's own window, which pages cannot
// cover or restyle.

import type { LoginChoice, PairingState, View } from "./background.js";

const main = document.getElementById("main") as HTMLElement;
const site = document.getElementById("site") as HTMLElement;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
  cls?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}

function show(...nodes: Node[]) {
  main.replaceChildren(...nodes);
}

function send<T>(message: object): Promise<T> {
  return chrome.runtime.sendMessage(message) as Promise<T>;
}

function message(title: string, body: string, action?: [string, () => void]) {
  const nodes: Node[] = [el("h1", title), el("p", body)];
  if (action) {
    const button = el("button", action[0], "primary");
    button.addEventListener("click", action[1]);
    nodes.push(button);
  }
  show(...nodes);
}

async function refresh() {
  render(await send<View>({ cmd: "state" }));
}

function render(view: View) {
  site.textContent = view.view === "logins" ? view.site : "";
  switch (view.view) {
    case "unpaired":
      return renderPairing(view.pairing);
    case "app_closed":
      return message(
        "Open BlackBoxus",
        "Make sure the BlackBoxus app is open on this computer, with Browser extension turned on in its Settings.",
        ["Try again", refresh],
      );
    case "disabled":
      return message(
        "Turn on the browser extension",
        "In the BlackBoxus app, open Settings and turn on Browser extension.",
        ["Try again", refresh],
      );
    case "no_account":
      return message("Set up BlackBoxus first", "Sign in to the BlackBoxus app on this computer.");
    case "locked":
      return message("BlackBoxus is locked", "Unlock the app on this computer, then try again.", [
        "Try again",
        refresh,
      ]);
    case "no_page":
      return message("Nothing to fill here", "BlackBoxus fills logins on web pages.");
    case "error":
      return message("Something went wrong", view.message, ["Try again", refresh]);
    case "logins":
      return renderLogins(view.logins, view.insecure);
  }
}

function renderLogins(logins: LoginChoice[], insecure: boolean) {
  const nodes: Node[] = [];
  if (insecure) {
    nodes.push(el("p", "This page isn't secure. Anyone on your network could see what you send.", "warn"));
  }
  if (logins.length === 0) {
    nodes.push(el("h1", "No logins for this site"), el("p", "Add one in the BlackBoxus app, with this site's address."));
    return show(...nodes);
  }
  const list = el("ul");
  for (const login of logins) {
    const item = el("li");
    const avatar = el("span", (login.title.trim()[0] ?? "?").toUpperCase(), "avatar");
    const who = el("span", undefined, "who");
    who.append(el("span", login.title || login.username), el("span", `${login.username} · ${login.vault_name}`, "sub"));
    const button = el("button", "Fill", "primary");
    button.setAttribute("aria-label", `Fill ${login.title}`);
    button.addEventListener("click", async () => {
      button.disabled = true;
      const result = await send<"filled" | "failed" | View>({ cmd: "fill", vault: login.vault, item: login.item });
      if (result === "filled") {
        window.close();
      } else if (result === "failed") {
        button.disabled = false;
        button.textContent = "No form found";
      } else {
        render(result);
      }
    });
    item.append(avatar, who, button);
    list.append(item);
  }
  nodes.push(list);
  show(...nodes);
}

function renderPairing(state: PairingState | null) {
  if (!state || state.status === "denied" || state.status === "failed") {
    const body =
      state?.status === "denied"
        ? "The app didn't allow this browser. Turn on Browser extension in BlackBoxus Settings, then pair again."
        : state?.status === "failed"
          ? "Couldn't reach the BlackBoxus app. Make sure it's open, with Browser extension turned on in Settings."
          : "Connect this browser to the BlackBoxus app on this computer. Your passwords stay in the app; the extension asks for one only when you fill it.";
    return message("Pair with BlackBoxus", body, ["Pair", startPairing]);
  }
  if (state.status === "paired") return void refresh();
  const nodes: Node[] = [el("h1", "Check the code")];
  if (state.code) {
    nodes.push(
      el("p", "BlackBoxus is asking whether to allow this browser. Allow it only if the app shows this code:"),
      el("div", `${state.code.slice(0, 3)} ${state.code.slice(3)}`, "code"),
      el("p", "Waiting for you to allow it in the app…", "small"),
    );
  } else {
    nodes.push(el("p", "Asking the app…"));
  }
  show(...nodes);
  setTimeout(async () => renderPairing(await send<PairingState | null>({ cmd: "pairing" })), 800);
}

async function startPairing() {
  renderPairing(await send<PairingState>({ cmd: "pair" }));
}

refresh();
