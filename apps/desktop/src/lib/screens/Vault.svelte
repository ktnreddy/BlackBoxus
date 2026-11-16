<script lang="ts">
  import Icon, { type IconName } from "../components/Icon.svelte";
  import Logo from "../components/Logo.svelte";
  import StatusBar from "../components/StatusBar.svelte";
  import {
    errorMessage,
    isAppError,
    listItems,
    lock,
    syncVaults,
    type AppStatus,
    type EmergencyKit,
    getSettings,
    type ItemSummary,
    type ItemView,
    type VaultSummary,
  } from "../api";
  import ItemDetail from "./vault/ItemDetail.svelte";
  import GeneratorDialog from "./vault/GeneratorDialog.svelte";
  import ImportDialog from "./vault/ImportDialog.svelte";
  import ItemEditor from "./vault/ItemEditor.svelte";
  import SettingsDialog from "./vault/SettingsDialog.svelte";
  import ShareVault from "./vault/ShareVault.svelte";

  let {
    status,
    onchange,
    onkit,
  }: {
    status: AppStatus;
    onchange: (s: AppStatus, why?: string) => void;
    onkit: (kit: EmergencyKit) => void;
  } = $props();

  /** Lock after this many minutes without keyboard or mouse input. */
  let autoLockMinutes = $state(10);
  getSettings().then(
    (s) => (autoLockMinutes = s.auto_lock_minutes),
    () => {},
  );

  let vaults = $state<VaultSummary[]>([]);
  let vaultId = $state<string | null>(null);
  let items = $state<ItemSummary[]>([]);
  let selected = $state<string | null>(null);
  let editing = $state<ItemView | "new" | null>(null);
  let filter = $state<"all" | "login" | "card" | "note">("all");
  let query = $state("");
  let syncing = $state(true);
  let syncError = $state("");
  let syncedAt = $state<number | null>(null);
  /** Showing this computer's copy because the server can't be reached. */
  let offline = $state(false);
  let notice = $state("");
  let sharing = $state(false);
  let generatorOpen = $state(false);
  let importOpen = $state(false);
  let settingsOpen = $state(false);
  let now = $state(Date.now());

  const found = $derived(vaults.find((v) => v.id === vaultId) ?? null);
  /** While offline, every vault is read-only. */
  const vault = $derived(found && offline ? { ...found, writable: false } : found);
  const shownItems = $derived(
    items.filter(
      (i) =>
        (filter === "all" || i.type === filter) &&
        (query.trim() === "" ||
          `${i.title} ${i.subtitle}`.toLowerCase().includes(query.trim().toLowerCase())),
    ),
  );

  async function refreshItems() {
    if (!vaultId) return;
    try {
      items = await listItems(vaultId);
    } catch (e) {
      notice = errorMessage(e);
    }
  }

  async function sync() {
    syncing = true;
    syncError = "";
    try {
      const synced = await syncVaults();
      vaults = synced.vaults;
      offline = synced.offline;
      if (!vaults.some((v) => v.id === vaultId)) vaultId = vaults[0]?.id ?? null;
      syncedAt = Date.now();
      await refreshItems();
    } catch (e) {
      if (isAppError(e) && e.code === "signed_out") {
        // The saved session expired: the master password is needed.
        onchange(
          await lock(),
          offline
            ? "You're back online. Unlock with your master password to sync and make changes."
            : "Your session ended. Unlock with your master password.",
        );
        return;
      }
      syncError = errorMessage(e);
    } finally {
      syncing = false;
    }
  }

  async function lockNow() {
    onchange(await lock());
  }

  sync();

  // Keep "synced n minutes ago" fresh, and lock when idle.
  $effect(() => {
    const tick = setInterval(() => (now = Date.now()), 30_000);
    let last = Date.now();
    const touch = () => (last = Date.now());
    const idle = setInterval(() => {
      if (Date.now() - last > autoLockMinutes * 60_000) lockNow();
    }, 15_000);
    window.addEventListener("keydown", touch);
    window.addEventListener("pointerdown", touch);
    window.addEventListener("pointermove", touch);
    return () => {
      clearInterval(tick);
      clearInterval(idle);
      window.removeEventListener("keydown", touch);
      window.removeEventListener("pointerdown", touch);
      window.removeEventListener("pointermove", touch);
    };
  });

  let noticeTimer: ReturnType<typeof setTimeout> | undefined;
  function showNotice(text: string) {
    notice = text;
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => (notice = ""), 4000);
  }

  function chooseVault(id: string) {
    vaultId = id;
    sharing = false;
    selected = null;
    editing = null;
    refreshItems();
  }

  async function saved(id: string) {
    editing = null;
    await refreshItems();
    vaults = vaults.map((v) => (v.id === vaultId ? { ...v, items: items.length } : v));
    selected = id;
    syncedAt = Date.now();
    showNotice("Saved and synced.");
  }

  async function deleted() {
    selected = null;
    await refreshItems();
    vaults = vaults.map((v) => (v.id === vaultId ? { ...v, items: items.length } : v));
    syncedAt = Date.now();
    showNotice("Deleted.");
  }

  function ago(at: number, current: number): string {
    const minutes = Math.floor((current - at) / 60_000);
    if (minutes < 1) return "just now";
    if (minutes === 1) return "a minute ago";
    if (minutes < 60) return `${minutes} minutes ago`;
    return "over an hour ago";
  }

  const FILTERS: [typeof filter, string, IconName][] = [
    ["all", "All items", "grid"],
    ["login", "Logins", "login"],
    ["card", "Cards", "card"],
    ["note", "Secure notes", "note"],
  ];
</script>

{#if syncing}
  <StatusBar icon="refresh" tone="quiet">Syncing and checking your vaults…</StatusBar>
{:else if offline}
  <StatusBar icon="alert" tone="quiet">
    Offline. Showing the copy on this computer, read-only. Use sync to try again.
  </StatusBar>
{:else if syncError}
  <StatusBar icon="alert" tone="quiet">{syncError}</StatusBar>
{:else}
  <StatusBar icon="shield">
    Verified and synced {syncedAt ? ago(syncedAt, now) : ""} · history checked
  </StatusBar>
{/if}

<div class="layout">
  <nav class="side" aria-label="Vaults">
    <div class="brand"><Logo /></div>
    <div class="small group">Vaults</div>
    {#each vaults as v (v.id)}
      <button
        type="button"
        class="side-item"
        class:on={v.id === vaultId}
        aria-current={v.id === vaultId ? "page" : undefined}
        onclick={() => chooseVault(v.id)}
      >
        <span class="side-name"><span class="dot" class:on={v.id === vaultId}></span>{v.name}</span>
        <span class="count">{v.items}</span>
      </button>
    {/each}
    {#if vault && !offline}
      <button
        type="button"
        class="side-item plain"
        class:on={sharing}
        aria-pressed={sharing}
        onclick={() => (sharing = !sharing)}
      >
        <span class="side-name"><Icon name="users" size={16} />Share {vault.name}</span>
      </button>
    {/if}
    <div class="rule spacer"></div>
    <div class="small group">Show</div>
    {#each FILTERS as [value, text, icon] (value)}
      <button
        type="button"
        class="side-item plain"
        class:on={filter === value}
        aria-pressed={filter === value}
        onclick={() => {
          filter = value;
          sharing = false;
        }}
      >
        <span class="side-name"><Icon name={icon} size={16} />{text}</span>
      </button>
    {/each}
    <div class="rule spacer"></div>
    <button type="button" class="side-item plain" onclick={() => (generatorOpen = true)}>
      <span class="side-name"><Icon name="wand" size={16} />Password generator</span>
    </button>
    <button
      type="button"
      class="side-item plain"
      disabled={offline}
      onclick={() => (importOpen = true)}
    >
      <span class="side-name"><Icon name="upload" size={16} />Import passwords</span>
    </button>
    <div class="side-foot">
      <button type="button" class="btn ghost sm grow" onclick={lockNow}>
        <Icon name="lock" size={15} />Lock now
      </button>
      <button
        type="button"
        class="icon-btn"
        aria-label="Settings"
        onclick={() => (settingsOpen = true)}
      >
        <Icon name="gear" />
      </button>
      <button
        type="button"
        class="icon-btn"
        aria-label="Sync now"
        disabled={syncing}
        onclick={sync}
      >
        <Icon name="refresh" />
      </button>
    </div>
  </nav>

  {#if sharing && vault}
    <main class="glow detail wide">
      <ShareVault
        {vault}
        onclose={() => (sharing = false)}
        onnotice={showNotice}
        onleft={async () => {
          sharing = false;
          vaultId = null;
          await sync();
        }}
      />
      {#if notice}
        <div class="toast" role="status"><Icon name="check" size={16} />{notice}</div>
      {/if}
    </main>
  {:else}
  <section class="list" aria-label="Items">
    <div class="list-head">
      <label class="field search">
        <Icon name="search" size={16} />
        <span class="visually-hidden">Search</span>
        <input type="search" bind:value={query} placeholder={`Search ${vault?.name ?? ""}`} />
      </label>
      <button
        type="button"
        class="btn primary add"
        aria-label="New item"
        disabled={!vault?.writable}
        onclick={() => {
          editing = "new";
          selected = null;
        }}
      >
        <Icon name="plus" />
      </button>
    </div>
    <div class="small list-count">
      {shownItems.length}
      {shownItems.length === 1 ? "item" : "items"}
    </div>
    <ul class="items">
      {#each shownItems as i (i.id)}
        <li>
          <button
            type="button"
            class="item"
            class:on={i.id === selected && editing === null}
            onclick={() => {
              selected = i.id;
              editing = null;
            }}
          >
            <span class="letter" aria-hidden="true">{i.title.slice(0, 1).toUpperCase()}</span>
            <span class="item-text">
              <span class="item-title">{i.title}</span>
              <span class="small item-sub">{i.subtitle}</span>
            </span>
          </button>
        </li>
      {/each}
    </ul>
    {#if !syncing && items.length === 0 && vault}
      <p class="small empty">Nothing here yet. Add your first password with the + button.</p>
    {/if}
  </section>

  <main class="glow detail">
    {#if vault && editing !== null}
      <ItemEditor
        vault={vault.id}
        existing={editing === "new" ? null : editing}
        onsaved={saved}
        oncancel={() => (editing = null)}
        onnotice={showNotice}
      />
    {:else if vault && selected}
      <ItemDetail
        vault={vault.id}
        vaultName={vault.name}
        itemId={selected}
        writable={vault.writable}
        onedit={(item) => (editing = item)}
        ondeleted={deleted}
        onnotice={showNotice}
      />
    {:else}
      <div class="placeholder">
        <h1 class="display">Your vaults are <span class="hi">open.</span></h1>
        <p class="lede">Pick an item on the left, or add a new one.</p>
      </div>
    {/if}
    {#if notice}
      <div class="toast" role="status"><Icon name="check" size={16} />{notice}</div>
    {/if}
  </main>
  {/if}
</div>

{#if settingsOpen}
  <SettingsDialog
    {status}
    {offline}
    autoLock={autoLockMinutes}
    onautolock={(m) => (autoLockMinutes = m)}
    onkit={(k) => {
      settingsOpen = false;
      onkit(k);
    }}
    onchange={(s) => onchange(s)}
    onclose={() => (settingsOpen = false)}
    onnotice={showNotice}
  />
{/if}

{#if importOpen}
  <ImportDialog
    {vaults}
    current={vaultId}
    onclose={() => (importOpen = false)}
    ondone={async (id) => {
      vaultId = id;
      sharing = false;
      await sync();
    }}
  />
{/if}

{#if generatorOpen}
  <GeneratorDialog onclose={() => (generatorOpen = false)} onnotice={showNotice} />
{/if}

<style>
  .layout {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: 232px 320px minmax(0, 1fr);
  }
  .side {
    background: var(--side);
    border-right: 1px solid var(--hair);
    padding: 20px 14px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-height: 0;
  }
  .brand {
    padding: 0 6px 18px;
  }
  .group {
    padding: 0 14px 6px;
  }
  .side-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 40px;
    padding: 0 14px;
    border-radius: 999px;
    border: 0;
    background: transparent;
    color: var(--muted);
    font-size: 14px;
    cursor: pointer;
    text-align: left;
  }
  .side-item:hover:not(:disabled) {
    color: var(--text);
  }
  .side-item:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .side-item.on {
    background: var(--panel-2);
    color: var(--text);
  }
  .side-item.plain.on {
    background: transparent;
  }
  .side-name {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #3f3f46;
  }
  .dot.on {
    background: var(--accent);
  }
  .count {
    font-size: 13px;
    color: var(--dim);
  }
  .spacer {
    margin: 12px 6px;
  }
  .side-foot {
    margin-top: auto;
    display: flex;
    gap: 8px;
    padding: 0 6px;
  }
  .grow {
    flex: 1;
  }

  .list {
    border-right: 1px solid var(--hair);
    padding: 20px 16px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    min-height: 0;
  }
  .list-head {
    display: flex;
    gap: 8px;
  }
  .search {
    height: 44px;
    flex: 1;
    min-width: 0;
    padding-left: 16px;
    color: var(--dim);
  }
  .search input {
    font-size: 14px;
    color: var(--text);
  }
  .search input::placeholder {
    color: var(--dim);
  }
  .add {
    height: 44px;
    width: 44px;
    padding: 0;
    flex: none;
  }
  .list-count {
    padding: 4px 8px 0;
  }
  .items {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
    overflow-y: auto;
    min-height: 0;
  }
  .item {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    border-radius: 16px;
    border: 1px solid transparent;
    background: transparent;
    cursor: pointer;
    text-align: left;
  }
  .item:hover {
    background: var(--panel);
  }
  .item.on {
    background: var(--panel);
    border-color: var(--accent-line);
  }
  .letter {
    width: 36px;
    height: 36px;
    border-radius: 12px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 15px;
    font-weight: 500;
    flex: none;
  }
  .item-text {
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .item-title {
    font-size: 15px;
    font-weight: 500;
  }
  .item-sub,
  .item-title {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .empty {
    padding: 0 8px;
  }

  .detail {
    position: relative;
    padding: 36px 48px;
    display: flex;
    flex-direction: column;
    gap: 22px;
    min-height: 0;
    overflow-y: auto;
  }
  .wide {
    grid-column: 2 / 4;
  }
  .placeholder {
    margin: auto 0;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .toast {
    position: absolute;
    right: 48px;
    top: 24px;
    display: flex;
    align-items: center;
    gap: 10px;
    height: 40px;
    padding: 0 18px;
    border-radius: 999px;
    background: #24150b;
    color: var(--accent-soft);
    font-size: 14px;
  }
</style>
