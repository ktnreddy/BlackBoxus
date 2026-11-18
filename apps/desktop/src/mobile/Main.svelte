<script lang="ts">
  import Icon from "./Icon.svelte";
  import Sheet from "./Sheet.svelte";
  import VaultsTab from "./VaultsTab.svelte";
  import ItemPage from "./ItemPage.svelte";
  import EditItem from "./EditItem.svelte";
  import GeneratorTab from "./GeneratorTab.svelte";
  import SecurityTab from "./SecurityTab.svelte";
  import SettingsTab from "./SettingsTab.svelte";
  import SharePage from "./SharePage.svelte";
  import NameVault from "./NameVault.svelte";
  import ConflictPage from "./ConflictPage.svelte";
  import { back, opened } from "./nav";
  import type { IconName } from "./icons";
  import { tint } from "./tint";
  import {
    copyField,
    deleteItem,
    errorMessage,
    getItem,
    openWebsite,
    getSettings,
    isAppError,
    listItems,
    lock,
    pendingChanges,
    onServerHint,
    syncVaults,
    denyEmergency,
    type AppStatus,
    type EmergencyKit,
    type GrantView,
    type ItemSummary,
    type ItemType,
    type ItemView,
    type VaultSummary,
  } from "../lib/api";

  let {
    status,
    onchange,
    onkit,
  }: {
    status: AppStatus;
    onchange: (s: AppStatus, why?: string) => void;
    onkit: (kit: EmergencyKit) => void;
  } = $props();

  type Tab = "vaults" | "generator" | "security" | "settings";
  const TABS: { id: Tab; label: string; icon: IconName }[] = [
    { id: "vaults", label: "Vaults", icon: "vault" },
    { id: "generator", label: "Generator", icon: "wand" },
    { id: "security", label: "Security", icon: "shield" },
    { id: "settings", label: "Settings", icon: "settings" },
  ];
  let tab = $state<Tab>("vaults");

  type Shown =
    | { kind: "item"; id: string }
    | { kind: "edit"; item: ItemView | null; type: "login" | "note" | "card" }
    | { kind: "share" }
    | { kind: "name"; mode: "new" | "rename" }
    | { kind: "conflicts" };
  let pages = $state<Shown[]>([]);
  const page = $derived(pages.at(-1) ?? null);

  type SheetKind = { kind: "vaults" } | { kind: "item"; item: ItemSummary };
  let sheet = $state<SheetKind | null>(null);

  function show(next: Shown) {
    pages.push(next);
    opened(() => pages.pop());
  }
  function openSheet(next: SheetKind) {
    sheet = next;
    opened(() => (sheet = null));
  }

  let vaults = $state<VaultSummary[]>([]);
  let vaultId = $state<string | null>(null);
  let items = $state<ItemSummary[]>([]);
  let syncing = $state(true);
  let offline = $state(false);
  let syncedAt = $state<number | null>(null);
  let unknownKeys = $state(false);
  let emergencyRequest = $state<GrantView | null>(null);
  let toast = $state("");
  let autoLockMinutes = $state(10);

  const vault = $derived(vaults.find((v) => v.id === vaultId) ?? null);
  // Offline, changes are kept on this phone and sent once back online.
  const writable = $derived(vault !== null && vault.writable);
  let waiting = $state(0);
  let conflicts = $state(0);

  async function refreshPending() {
    try {
      const p = await pendingChanges();
      waiting = p.waiting;
      conflicts = p.conflicts.length;
    } catch {
      // The counts are only a hint; the next sync tries again.
    }
  }

  // While offline, try again every 30 seconds and as soon as the phone
  // says it's back online, so waiting changes go out by themselves.
  $effect(() => {
    if (!offline) return;
    const retry = () => {
      if (!syncing) sync();
    };
    const timer = setInterval(retry, 30_000);
    window.addEventListener("online", retry);
    return () => {
      clearInterval(timer);
      window.removeEventListener("online", retry);
    };
  });

  getSettings().then(
    (s) => (autoLockMinutes = s.auto_lock_minutes),
    () => {},
  );

  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  function notify(text: string) {
    toast = text;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = ""), 3500);
  }

  async function refreshItems() {
    if (!vaultId) {
      items = [];
      return;
    }
    try {
      items = await listItems(vaultId);
    } catch (e) {
      notify(errorMessage(e));
    }
  }

  async function sync() {
    syncing = true;
    try {
      const synced = await syncVaults();
      vaults = synced.vaults;
      offline = synced.offline;
      unknownKeys = synced.unknown_keys;
      emergencyRequest = synced.emergency_request;
      waiting = synced.waiting;
      conflicts = synced.conflicts;
      if (!vaults.some((v) => v.id === vaultId)) vaultId = vaults[0]?.id ?? null;
      syncedAt = Date.now();
      await refreshItems();
    } catch (e) {
      if (isAppError(e) && e.code === "signed_out") {
        onchange(
          await lock(),
          offline
            ? "You're back online. Unlock with your master password to sync."
            : "Your session ended. Unlock with your master password.",
        );
        return;
      }
      notify(errorMessage(e));
    } finally {
      syncing = false;
    }
  }

  async function lockNow() {
    onchange(await lock());
  }

  sync();

  // Sync shortly after the server says something changed.
  $effect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const soon = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        if (syncing || page?.kind === "edit") soon();
        else sync();
      }, 1500);
    };
    const stop = onServerHint(() => soon());
    return () => {
      clearTimeout(timer);
      stop.then((f) => f()).catch(() => {});
    };
  });

  // Lock after the chosen time without a touch, or when the app comes
  // back after being away that long.
  $effect(() => {
    let last = Date.now();
    const touch = () => (last = Date.now());
    // "Straight away" (0) locks on leaving the app, and after a minute
    // without a touch while open.
    const idleMs = Math.max(1, autoLockMinutes) * 60_000;
    const idle = setInterval(() => {
      if (Date.now() - last > idleMs) lockNow();
    }, 15_000);
    let hiddenAt: number | null = null;
    const visibility = () => {
      if (document.hidden) {
        hiddenAt = Date.now();
      } else if (hiddenAt !== null) {
        if (Date.now() - hiddenAt >= autoLockMinutes * 60_000) lockNow();
        else if (!syncing) sync();
        hiddenAt = null;
        touch();
      }
    };
    window.addEventListener("pointerdown", touch);
    window.addEventListener("keydown", touch);
    document.addEventListener("visibilitychange", visibility);
    return () => {
      clearInterval(idle);
      window.removeEventListener("pointerdown", touch);
      window.removeEventListener("keydown", touch);
      document.removeEventListener("visibilitychange", visibility);
    };
  });

  function chooseVault(id: string) {
    vaultId = id;
    refreshItems();
    back();
  }

  async function saved(id: string, target: string, wasNew: boolean) {
    vaultId = target;
    await refreshItems();
    vaults = vaults.map((v) => (v.id === vaultId ? { ...v, items: items.length } : v));
    back();
    if (offline) {
      await refreshPending();
      notify("Saved on this phone. It syncs when you're back online.");
    } else {
      syncedAt = Date.now();
      notify("Saved and synced.");
    }
    if (wasNew) show({ kind: "item", id });
  }

  async function deleted() {
    await refreshItems();
    vaults = vaults.map((v) => (v.id === vaultId ? { ...v, items: items.length } : v));
    if (offline) await refreshPending();
    notify(offline ? "Deleted on this phone. It syncs when you're back online." : "Deleted.");
  }



  /** Copies the first field of `kind` from an item, from the list. */
  async function copyKind(item: ItemSummary, kind: string, fromSheet = true) {
    if (!vault) return;
    try {
      const full = await getItem(vault.id, item.id);
      const index = full.fields.findIndex((f) => f.kind === kind);
      if (index < 0) {
        notify(kind === "password" ? "This login has no password." : "Nothing to copy.");
      } else {
        await copyField(vault.id, item.id, index);
        notify(
          kind === "username"
            ? "Username copied"
            : kind === "card_number"
              ? "Card number copied · clears in 30 s"
              : "Password copied · clears in 30 s",
        );
      }
    } catch (e) {
      notify(errorMessage(e));
    }
    if (fromSheet) back();
  }


  async function openSite(item: ItemSummary) {
    if (!vault) return;
    try {
      await openWebsite(vault.id, item.id);
    } catch (e) {
      notify(errorMessage(e));
    }
    back();
  }

  async function editFromSheet(item: ItemSummary) {
    if (!vault) return;
    try {
      const full = await getItem(vault.id, item.id);
      back();
      setTimeout(
        () =>
          show({
            kind: "edit",
            item: full,
            type: full.type === "note" || full.type === "card" ? full.type : "login",
          }),
        0,
      );
    } catch (e) {
      notify(errorMessage(e));
    }
  }

  let confirmRemove = $state(false);
  let removing = $state(false);
  async function removeFromSheet(item: ItemSummary) {
    if (!vault || removing) return;
    if (!confirmRemove) {
      confirmRemove = true;
      return;
    }
    removing = true;
    try {
      await deleteItem(vault.id, item.id);
      confirmRemove = false;
      back();
      // Close the item's page too, if it's open.
      if (page?.kind === "item" && page.id === item.id) setTimeout(back, 0);
      await deleted();
    } catch (e) {
      notify(errorMessage(e));
    } finally {
      removing = false;
    }
  }
  $effect(() => {
    if (sheet === null) confirmRemove = false;
  });

  let denying = $state(false);
  async function deny() {
    if (!emergencyRequest || denying) return;
    denying = true;
    try {
      await denyEmergency(emergencyRequest.sharing_id);
      emergencyRequest = null;
      notify("Request denied.");
    } catch (e) {
      notify(errorMessage(e));
    } finally {
      denying = false;
    }
  }

  const TYPE_ICON: Record<ItemType, IconName> = {
    login: "login",
    card: "card",
    note: "note",
    identity: "identity",
    api: "api",
  };
</script>

<div class="shell">
  {#if tab === "vaults"}
    <VaultsTab
      {vault}
      {items}
      {offline}
      {syncing}
      {unknownKeys}
      {emergencyRequest}
      {denying}
      {writable}
      {waiting}
      {conflicts}
      onconflicts={() => show({ kind: "conflicts" })}
      onvaults={() => openSheet({ kind: "vaults" })}
      onitem={(i) => show({ kind: "item", id: i.id })}
      onmore={(i) => openSheet({ kind: "item", item: i })}
      oncopy={(i) => copyKind(i, i.type === "card" ? "card_number" : "password", false)}
      onadd={() => show({ kind: "edit", item: null, type: "login" })}
      onsync={sync}
      ondeny={deny}
      onlock={lockNow}
    />
  {:else if tab === "generator"}
    <GeneratorTab onnotice={notify} />
  {:else if tab === "security"}
    <SecurityTab
      {vaults}
      onopen={async (v, id) => {
        // Fixing a password means editing it: open the login's edit page.
        vaultId = v;
        refreshItems();
        try {
          const full = await getItem(v, id);
          show({ kind: "edit", item: full, type: full.type === "note" || full.type === "card" ? full.type : "login" });
        } catch (e) {
          notify(errorMessage(e));
        }
      }}
    />
  {:else}
    <SettingsTab
      {status}
      {autoLockMinutes}
      onautolock={(m) => (autoLockMinutes = m)}
      {onchange}
      {onkit}
      onnotice={notify}
      {vaults}
      {offline}
      {syncedAt}
    />
  {/if}

  <nav class="nav" aria-label="Main">
    {#each TABS as t (t.id)}
      <button
        type="button"
        class="tab"
        class:on={tab === t.id}
        aria-current={tab === t.id ? "page" : undefined}
        onclick={() => (tab = t.id)}
      >
        <span class="pill"><Icon name={t.icon} size={20} /></span>{t.label}
      </button>
    {/each}
  </nav>
</div>

{#if page?.kind === "item" && vault}
  {@const summary = items.find((i) => i.id === (page?.kind === "item" ? page.id : ""))}
  <ItemPage
    vault={vault.id}
    vaultName={vault.name}
    itemId={page.id}
    subtitle={summary?.subtitle ?? ""}
    {writable}
    onedit={(item) =>
      show({
        kind: "edit",
        item,
        type: item.type === "note" || item.type === "card" ? item.type : "login",
      })}
    onmore={() => summary && openSheet({ kind: "item", item: summary })}
    onnotice={notify}
  />
{/if}
{#if page?.kind === "edit" && vault}
  {#key page}
    <EditItem
      {vault}
      {vaults}
      existing={page.item}
      type={page.type}
      onsaved={(id, v) => saved(id, v, page?.kind === "edit" && page.item === null)}
    />
  {/key}
{/if}
{#if page?.kind === "share" && vault}
  <SharePage {vault} onnotice={notify} onchanged={sync} />
{/if}
{#if page?.kind === "conflicts"}
  <ConflictPage
    onresolved={async (left) => {
      conflicts = left;
      await refreshItems();
      if (left === 0) back();
    }}
    onnotice={notify}
  />
{/if}
{#if page?.kind === "name"}
  <NameVault
    mode={page.mode}
    {vault}
    ondone={(list, id) => {
      vaults = list;
      if (id) vaultId = id;
      refreshItems();
      back();
    }}
  />
{/if}

{#if sheet?.kind === "vaults"}
  <Sheet label="Switch vault">
    <h2 class="sh-title">Your vaults</h2>
    {#each vaults as v (v.id)}
      <button type="button" class="vrow" class:current={v.id === vaultId} onclick={() => chooseVault(v.id)}>
        <span class="vbadge {tint(v.name)}">{v.name[0]?.toUpperCase() ?? "?"}</span>
        <span class="vtext">
          <span class="vname">{v.name}</span>
          <span class="vmeta">
            {v.items}
            {v.items === 1 ? "item" : "items"} · {v.owner ? (v.shared ? "shared" : "only you") : "shared with you"}{v.writable
              ? ""
              : " · view only"}
          </span>
        </span>
        {#if v.id === vaultId}
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ff6a1a" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" role="img" aria-label="Current vault"><path d="M20 6 9 17l-5-5" /></svg>
        {/if}
      </button>
    {/each}
    <div class="vbtns">
      <button
        type="button"
        class="vbtn"
        disabled={offline}
        onclick={() => {
          back();
          setTimeout(() => show({ kind: "name", mode: "new" }), 0);
        }}>New vault</button
      >
      <button
        type="button"
        class="vbtn"
        disabled={!vault || offline}
        onclick={() => {
          back();
          setTimeout(() => show({ kind: "share" }), 0);
        }}>{vault ? `Share ${vault.name}` : "Share"}</button
      >
    </div>
  </Sheet>
{:else if sheet?.kind === "item"}
  {@const it = sheet.item}
  <Sheet label={`${it.title} actions`} gap={4} actions>
    <div class="ihead">
      <span class="ibadge {tint(it.title)}">
        {#if it.type === "login"}{it.title[0]?.toUpperCase() ?? "?"}{:else}<Icon name={TYPE_ICON[it.type]} size={22} />{/if}
      </span>
      <span class="itext"><span class="iname">{it.title}</span><span class="isub">{it.subtitle}</span></span>
    </div>
    {#if it.type === "login"}
      <button type="button" class="act" onclick={() => copyKind(it, "password")}>
        <span class="aic accent"><Icon name="copy" size={22} weight={1.8} /></span>Copy password
      </button>
      <button type="button" class="act" onclick={() => copyKind(it, "username")}>
        <span class="aic"><Icon name="copy" size={22} weight={1.8} /></span>Copy username
      </button>
      {#if it.site}
        <button type="button" class="act" onclick={() => openSite(it)}>
          <span class="aic"><Icon name="open" size={22} weight={1.8} /></span><span class="aclip">Open {it.site}</span>
        </button>
      {/if}
    {:else if it.type === "card"}
      <button type="button" class="act" onclick={() => copyKind(it, "card_number")}>
        <span class="aic accent"><Icon name="copy" size={22} weight={1.8} /></span>Copy card number
      </button>
    {/if}
    {#if writable}
      <button type="button" class="act" onclick={() => editFromSheet(it)}>
        <span class="aic"><Icon name="edit" size={22} weight={1.8} /></span>Edit
      </button>
      <button type="button" class="act danger" onclick={() => removeFromSheet(it)} disabled={removing}>
        <span class="aic"><Icon name="trash" size={22} weight={1.8} /></span>{confirmRemove ? "Tap again to delete for good" : "Delete"}
      </button>
    {/if}
  </Sheet>
{/if}

{#if toast}
  <div class="toast" class:low={page !== null} role="status"><Icon name="check" size={18} />{toast}</div>
{/if}

<style>
  .shell {
    width: 100%;
    height: 100%;
    box-sizing: border-box;
    background: #0b0b0c;
    color: #f4f4f5;
    display: flex;
    flex-direction: column;
    position: relative;
    overflow: hidden;
  }
  .nav {
    height: calc(80px + var(--bb));
    box-sizing: border-box;
    padding: 8px 12px calc(18px + var(--bb));
    border-top: 1px solid #1f1f22;
    background: #0b0b0c;
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    flex: none;
  }
  .tab {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    border: 0;
    background: none;
    color: #a1a1aa;
    font-size: 12px;
    font-weight: 500;
  }
  .tab.on {
    color: #ff6a1a;
  }
  .pill {
    width: 56px;
    height: 30px;
    display: grid;
    place-items: center;
  }
  .tab.on .pill {
    border-radius: 15px;
    background: rgba(255, 106, 26, 0.14);
  }
  .sh-title {
    margin: 0 8px 8px;
    font-size: 20px;
    font-weight: 500;
  }
  .vrow {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 64px;
    padding: 0 10px;
    border: 0;
    border-radius: 16px;
    background: transparent;
    color: #f4f4f5;
    text-align: left;
  }
  .vrow.current {
    background: rgba(255, 106, 26, 0.08);
  }
  .vbadge {
    width: 44px;
    height: 44px;
    flex: none;
    border-radius: 12px;
    background: #1c1c1f;
    display: grid;
    place-items: center;
    font-weight: 600;
  }
  .vtext {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .vname {
    font-size: 16px;
    font-weight: 500;
  }
  .vmeta {
    font-size: 13px;
    color: #a1a1aa;
  }
  .vbtns {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
    margin-top: 10px;
  }
  .vbtn {
    min-width: 0;
    padding: 0 16px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-height: 52px;
    border-radius: 26px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #f4f4f5;
    font: 500 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .vbtn:disabled {
    opacity: 0.45;
  }
  .ihead {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 0 8px 14px;
  }
  .ibadge {
    width: 48px;
    height: 48px;
    flex: none;
    border-radius: 13px;
    background: #1c1c1f;
    display: grid;
    place-items: center;
    font-weight: 600;
    font-size: 18px;
  }
  .itext {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .iname,
  .isub {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .iname {
    font-size: 18px;
    font-weight: 500;
  }
  .isub {
    font-size: 14px;
    color: #a1a1aa;
  }
  .act {
    display: flex;
    align-items: center;
    gap: 16px;
    min-height: 56px;
    padding: 0 12px;
    border: 0;
    border-radius: 14px;
    background: none;
    color: #f4f4f5;
    font: 400 16px "DM Sans Variable", sans-serif;
    text-align: left;
  }
  .aclip {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .act.danger {
    color: #fca5a5;
  }
  .aic {
    width: 24px;
    height: 24px;
    display: grid;
    place-items: center;
    color: #d4d4d8;
  }
  .aic.accent {
    color: #ff6a1a;
  }
  .danger .aic {
    color: #fca5a5;
  }
  .toast {
    position: fixed;
    left: 16px;
    right: 16px;
    bottom: calc(96px + var(--bb));
    z-index: 40;
    padding: 14px 18px;
    border-radius: 16px;
    background: #f4f4f5;
    color: #0b0b0c;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 15px;
    font-weight: 500;
  }
  .toast.low {
    bottom: calc(28px + var(--bb));
  }
</style>
