<script lang="ts">
  import Icon, { type IconName } from "../components/Icon.svelte";
  import Logo from "../components/Logo.svelte";
  import StatusBar from "../components/StatusBar.svelte";
  import {
    denyEmergency,
    errorMessage,
    getItem,
    isAppError,
    listItems,
    localVaults,
    onServerHint,
    lock,
    pendingChanges,
    syncVaults,
    type AppStatus,
    type EmergencyKit,
    type GrantView,
    getSettings,
    type ItemSummary,
    type ItemView,
    type VaultSummary,
  } from "../api";
  import ItemDetail from "./vault/ItemDetail.svelte";
  import GeneratorDialog from "./vault/GeneratorDialog.svelte";
  import ImportDialog from "./vault/ImportDialog.svelte";
  import ExportDialog from "./vault/ExportDialog.svelte";
  import ItemEditor from "./vault/ItemEditor.svelte";
  import SettingsDialog from "./vault/SettingsDialog.svelte";
  import ShareVault from "./vault/ShareVault.svelte";
  import VaultNameDialog from "./vault/VaultNameDialog.svelte";
  import TrustedContactsDialog from "./vault/TrustedContactsDialog.svelte";
  import EmergencyViewer from "./vault/EmergencyViewer.svelte";
  import ConflictDialog from "./vault/ConflictDialog.svelte";
  import HealthDialog from "./vault/HealthDialog.svelte";

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
  /** Showing this device's copy because the server can't be reached. */
  let offline = $state(false);
  let notice = $state("");
  /** The key log lists keys for this account that it did not publish. */
  let unknownKeys = $state(false);
  /** The trusted contact has asked for access. */
  let emergencyRequest = $state<GrantView | null>(null);
  let trustedOpen = $state(false);
  /** Warnings closed with their X. They come back at the next sync if
   *  still true, and a new emergency request always shows. */
  let dismissed = $state<{ unknownKeys: boolean; request: number | null; syncError: boolean }>({
    unknownKeys: false,
    request: null,
    syncError: false,
  });
  /** Another account opened as its trusted contact. */
  let viewing = $state<{ owner: string; vaults: VaultSummary[] } | null>(null);
  let denying = $state(false);

  async function denyRequest() {
    if (!emergencyRequest || denying) return;
    denying = true;
    try {
      await denyEmergency(emergencyRequest.sharing_id);
      emergencyRequest = null;
      showNotice("Request denied.");
    } catch (e) {
      showNotice(errorMessage(e));
    } finally {
      denying = false;
    }
  }
  let sharing = $state(false);
  let generatorOpen = $state(false);
  let healthOpen = $state(false);
  let importOpen = $state(false);
  let exportOpen = $state(false);
  let settingsOpen = $state(false);
  /** Naming a vault: a new one, or renaming the one shown. */
  let naming = $state<"new" | "rename" | null>(null);
  let now = $state(Date.now());

  const found = $derived(vaults.find((v) => v.id === vaultId) ?? null);
  /** Offline, changes are kept on this computer and sent once back online. */
  const vault = $derived(found);
  /** Changes made offline, still to be sent. */
  let waiting = $state(0);
  /** Items changed both here and elsewhere, for the user to settle. */
  let conflicts = $state(0);
  let conflictsOpen = $state(false);

  async function refreshPending() {
    try {
      const p = await pendingChanges();
      waiting = p.waiting;
      conflicts = p.conflicts.length;
    } catch {
      // Only a hint; the next sync counts again.
    }
  }

  // While offline, try again every 30 seconds and when the network comes
  // back, so waiting changes go out by themselves.
  $effect(() => {
    if (!offline) return;
    const retry = () => {
      if (!syncing && !editing) sync();
    };
    const timer = setInterval(retry, 30_000);
    window.addEventListener("online", retry);
    return () => {
      clearInterval(timer);
      window.removeEventListener("online", retry);
    };
  });
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
    dismissed.syncError = false;
    try {
      const synced = await syncVaults();
      vaults = synced.vaults;
      offline = synced.offline;
      unknownKeys = synced.unknown_keys;
      dismissed.unknownKeys = false;
      emergencyRequest = synced.emergency_request;
      waiting = synced.waiting;
      conflicts = synced.conflicts;
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

  // Show this device's copy straight away; the sync then brings it up to
  // date in the background.
  localVaults().then(
    async (local) => {
      if (vaults.length > 0 || local.vaults.length === 0) return;
      vaults = local.vaults;
      waiting = local.waiting;
      conflicts = local.conflicts;
      if (!vaults.some((v) => v.id === vaultId)) vaultId = vaults[0]?.id ?? null;
      await refreshItems();
    },
    () => {},
  );
  sync();

  // Sync soon after the server says something changed, waiting for a
  // quiet moment so a burst of changes (an import elsewhere) syncs once.
  $effect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const soon = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        if (syncing || importOpen || editing) soon();
        else sync();
      }, 1500);
    };
    const stop = onServerHint(() => soon());
    return () => {
      clearTimeout(timer);
      stop.then((unlisten) => unlisten()).catch(() => {});
    };
  });

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
    chose();
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
    if (offline) {
      await refreshPending();
      showNotice("Saved on this computer. It syncs when you're back online.");
    } else {
      syncedAt = Date.now();
      showNotice("Saved and synced.");
    }
  }

  async function deleted() {
    selected = null;
    await refreshItems();
    vaults = vaults.map((v) => (v.id === vaultId ? { ...v, items: items.length } : v));
    if (offline) {
      await refreshPending();
      showNotice("Deleted on this computer. It syncs when you're back online.");
    } else {
      syncedAt = Date.now();
      showNotice("Deleted.");
    }
  }

  function ago(at: number, current: number): string {
    const minutes = Math.floor((current - at) / 60_000);
    if (minutes < 1) return "just now";
    if (minutes === 1) return "a minute ago";
    if (minutes < 60) return `${minutes} minutes ago`;
    return "over an hour ago";
  }

  // Phones and narrow windows show one pane at a time: the item list, or
  // the item (or sharing) with a back button, and the vault menu in a
  // drawer. Each step forward adds a history entry, so Android's back
  // gesture steps back through them.
  const narrowQuery = window.matchMedia("(max-width: 760px)");
  let narrow = $state(narrowQuery.matches);
  let drawerOpen = $state(false);
  $effect(() => {
    const update = () => {
      narrow = narrowQuery.matches;
      if (!narrow) drawerOpen = false;
    };
    narrowQuery.addEventListener("change", update);
    return () => narrowQuery.removeEventListener("change", update);
  });
  /** The pane shown on a narrow screen. */
  const pane = $derived(
    sharing ? "share" : editing !== null || selected !== null ? "detail" : "list",
  );
  /** History entries added for steps forward, not yet stepped back. */
  let pushed = 0;
  function forward() {
    if (!narrow) return;
    history.pushState({ blackboxus: true }, "");
    pushed += 1;
  }
  /** One step back: the drawer, then the editor, then the item. */
  function stepBack() {
    if (drawerOpen) drawerOpen = false;
    else if (sharing) sharing = false;
    else if (editing !== null) editing = null;
    else if (selected !== null) selected = null;
  }
  /** The on-screen back button, which uses the same history entries. */
  function back() {
    if (pushed > 0) history.back();
    else stepBack();
  }
  $effect(() => {
    const popped = () => {
      pushed = Math.max(0, pushed - 1);
      stepBack();
    };
    window.addEventListener("popstate", popped);
    return () => window.removeEventListener("popstate", popped);
  });
  function openDrawer() {
    drawerOpen = true;
    forward();
  }
  /** Closes the drawer after a choice in it. */
  function chose() {
    if (drawerOpen) back();
  }

  const FILTERS: [typeof filter, string, IconName][] = [
    ["all", "All items", "grid"],
    ["login", "Logins", "login"],
    ["card", "Cards", "card"],
    ["note", "Secure notes", "note"],
  ];
</script>

{#if unknownKeys && !dismissed.unknownKeys}
  <StatusBar icon="alert" tone="danger" ondismiss={() => (dismissed.unknownKeys = true)}>
    Warning: the public key log lists keys for your account that you didn't make. Someone may be
    posing as you to people who share with you. Don't share vaults until this is resolved.
  </StatusBar>
{:else if emergencyRequest && dismissed.request !== emergencyRequest.release_at_ms}
  <StatusBar
    icon="alert"
    tone="danger"
    ondismiss={() => (dismissed.request = emergencyRequest?.release_at_ms ?? null)}
  >
    Your trusted contact asked to see your vaults. Access opens on
    {new Date(emergencyRequest.release_at_ms ?? 0).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    })} unless you deny it.
    <button type="button" class="btn ghost sm deny" disabled={denying} onclick={denyRequest}>
      Deny
    </button>
  </StatusBar>
{:else if conflicts > 0}
  <StatusBar icon="alert" tone="danger">
    {conflicts === 1 ? "An item was" : `${conflicts} items were`} changed both here while offline and
    on another device.
    <button type="button" class="btn ghost sm deny" onclick={() => (conflictsOpen = true)}>Review</button>
  </StatusBar>
{:else if syncError && !dismissed.syncError}
  <StatusBar icon="alert" tone="danger" ondismiss={() => (dismissed.syncError = true)}>
    {syncError}
  </StatusBar>
{:else if vault && vault.newer > 0}
  <StatusBar icon="alert">
    {vault.newer === 1 ? "1 item in this vault was" : `${vault.newer} items in this vault were`} saved by a
    newer version of BlackBoxus. They're kept safe as they are; update this app to see them.
  </StatusBar>
{/if}

<div class="layout" class:narrow data-pane={pane}>
  {#if narrow}
    <header class="topbar">
      {#if pane === "list"}
        <button type="button" class="icon-btn" aria-label="Menu" onclick={openDrawer}>
          <Icon name="menu" />
        </button>
        <span class="top-title">{vault?.name ?? "BlackBoxus"}</span>
        <button
          type="button"
          class="icon-btn"
          aria-label="Sync now"
          disabled={syncing}
          onclick={sync}
        >
          <Icon name="refresh" />
        </button>
      {:else}
        <button type="button" class="icon-btn" aria-label="Back" onclick={back}>
          <Icon name="arrowLeft" />
        </button>
        <span class="top-title">{pane === "share" ? "Share this vault" : (vault?.name ?? "")}</span>
      {/if}
    </header>
    {#if drawerOpen}
      <button type="button" class="scrim" aria-label="Close menu" onclick={back}></button>
    {/if}
    {#if notice && pane === "list"}
      <div class="toast" role="status"><Icon name="check" size={16} />{notice}</div>
    {/if}
  {/if}
  <nav class="side" class:open={drawerOpen} aria-label="Vaults" inert={narrow && !drawerOpen}>
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
        <span class="side-name">
          <span class="dot" class:on={v.id === vaultId}></span>
          <span class="vault-name">{v.name}</span>
          {#if v.shared}<span class="shared" title="Shared"><Icon name="users" size={13} /></span>{/if}
        </span>
        <span class="count">{v.items}</span>
      </button>
    {/each}
    {#if !offline}
      <button
        type="button"
        class="side-item plain"
        onclick={() => {
          chose();
          naming = "new";
        }}
      >
        <span class="side-name"><Icon name="plus" size={16} />New vault</span>
      </button>
    {/if}
    {#if vault && !offline}
      <button
        type="button"
        class="side-item plain"
        class:on={sharing}
        aria-pressed={sharing}
        onclick={() => {
          chose();
          sharing = !sharing;
          if (sharing) forward();
        }}
      >
        <span class="side-name"><Icon name="users" size={16} />Share this vault</span>
      </button>
      {#if vault.writable}
        <button
          type="button"
          class="side-item plain"
          onclick={() => {
            chose();
            naming = "rename";
          }}
        >
          <span class="side-name"><Icon name="edit" size={16} />Rename this vault</span>
        </button>
      {/if}
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
          chose();
          filter = value;
          sharing = false;
        }}
      >
        <span class="side-name"><Icon name={icon} size={16} />{text}</span>
      </button>
    {/each}
    <div class="rule spacer"></div>
    <button
      type="button"
      class="side-item plain"
      onclick={() => {
        chose();
        generatorOpen = true;
      }}
    >
      <span class="side-name"><Icon name="wand" size={16} />Password generator</span>
    </button>
    <button
      type="button"
      class="side-item plain"
      onclick={() => {
        chose();
        healthOpen = true;
      }}
    >
      <span class="side-name"><Icon name="shield" size={16} />Password health</span>
    </button>
    <button
      type="button"
      class="side-item plain"
      disabled={offline}
      onclick={() => {
        chose();
        importOpen = true;
      }}
    >
      <span class="side-name"><Icon name="upload" size={16} />Import passwords</span>
    </button>
    <button
      type="button"
      class="side-item plain"
      onclick={() => {
        chose();
        exportOpen = true;
      }}
    >
      <span class="side-name"><Icon name="download" size={16} />Export vaults</span>
    </button>
    <button
      type="button"
      class="side-item plain"
      disabled={offline}
      onclick={() => {
        chose();
        trustedOpen = true;
      }}
    >
      <span class="side-name"><Icon name="key" size={16} />Trusted contacts</span>
    </button>
    <div
      class="sync-line small"
      class:warn={offline || !!syncError}
      role="status"
      title={syncError || undefined}
    >
      {#if syncing}
        <Icon name="refresh" size={14} />Syncing and checking…
      {:else if offline}
        <Icon name="alert" size={14} />Offline · {waiting > 0
          ? `${waiting} ${waiting === 1 ? "change" : "changes"} waiting`
          : "changes sync later"}
      {:else if syncError}
        <Icon name="alert" size={14} />Sync failed · try again
      {:else}
        <Icon name="shield" size={14} />Verified {syncedAt ? ago(syncedAt, now) : ""}
      {/if}
    </div>
    <div class="side-foot">
      <button
        type="button"
        class="btn ghost sm grow"
        onclick={() => {
          chose();
          lockNow();
        }}
      >
        <Icon name="lock" size={15} />Lock now
      </button>
      <button
        type="button"
        class="icon-btn"
        aria-label="Settings"
        onclick={() => {
          chose();
          settingsOpen = true;
        }}
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
          forward();
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
              forward();
            }}
          >
            <span class="letter" aria-hidden="true">{i.title.slice(0, 1).toUpperCase()}</span>
            <span class="item-text">
              <span class="item-title">{i.title}</span>
              <span class="small item-sub">{i.subtitle}</span>
            </span>
            {#if i.pending}
              <span class="pending" class:bad={i.pending === "conflict"}>
                {i.pending === "new" ? "New" : i.pending === "edited" ? "Edited" : "Conflict"}
              </span>
            {/if}
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
        onedit={(item) => {
          editing = item;
          forward();
        }}
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

{#if exportOpen}
  <ExportDialog
    email={status.account?.email ?? ""}
    onclose={() => (exportOpen = false)}
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

{#if naming}
  <VaultNameDialog
    vault={naming === "rename" ? vault : null}
    onclose={() => (naming = null)}
    ondone={(list, id) => {
      showNotice(naming === "rename" ? "Vault renamed." : "Vault created.");
      naming = null;
      vaults = list;
      chooseVault(id);
    }}
  />
{/if}

{#if trustedOpen}
  <TrustedContactsDialog
    onclose={() => {
      trustedOpen = false;
      sync();
    }}
    onopen={(owner, list) => {
      trustedOpen = false;
      viewing = { owner, vaults: list };
    }}
    onnotice={showNotice}
  />
{/if}

{#if viewing}
  <EmergencyViewer
    owner={viewing.owner}
    vaults={viewing.vaults}
    onclose={() => (viewing = null)}
    onnotice={showNotice}
  />
{/if}

{#if healthOpen}
  <HealthDialog
    onclose={() => (healthOpen = false)}
    onfix={async (v, id) => {
      // Fixing a password means editing it.
      healthOpen = false;
      chooseVault(v);
      try {
        editing = await getItem(v, id);
        selected = id;
        forward();
      } catch (e) {
        showNotice(errorMessage(e));
      }
    }}
  />
{/if}

{#if conflictsOpen}
  <ConflictDialog
    onclose={() => (conflictsOpen = false)}
    onnotice={showNotice}
    onresolved={async (left) => {
      conflicts = left;
      await refreshItems();
    }}
  />
{/if}

{#if generatorOpen}
  <GeneratorDialog onclose={() => (generatorOpen = false)} onnotice={showNotice} />
{/if}

<style>
  .deny {
    margin-left: 12px;
    padding: 2px 12px;
  }
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
    overflow-y: auto;
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
    min-width: 0;
  }
  .vault-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .shared {
    display: flex;
    color: var(--dim);
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
  .sync-line {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 10px 10px;
    color: var(--accent-soft);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .sync-line.warn {
    color: #ffb4a0;
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
  .pending {
    margin-left: auto;
    flex: none;
    padding: 2px 10px;
    border-radius: 999px;
    background: var(--panel-2);
    color: var(--accent-soft);
    font-size: 12px;
  }
  .pending.bad {
    color: #fca5a5;
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
  .topbar {
    display: none;
  }
  .scrim {
    display: none;
  }

  /* One pane at a time on phones and narrow windows. */
  .layout.narrow {
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: auto minmax(0, 1fr);
    position: relative;
  }
  .narrow .topbar {
    display: flex;
    align-items: center;
    gap: 8px;
    height: 56px;
    padding: 0 8px;
    border-bottom: 1px solid var(--hair);
    background: var(--bg);
  }
  .top-title {
    flex: 1;
    min-width: 0;
    font-size: 17px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .narrow .icon-btn {
    width: 44px;
    height: 44px;
  }
  .narrow .side {
    position: absolute;
    inset: 0 auto 0 0;
    z-index: 20;
    width: min(300px, 84vw);
    padding: 20px 14px calc(20px + env(safe-area-inset-bottom));
    border-right: 1px solid var(--line);
    transform: translateX(-102%);
    transition: transform 0.18s ease-out;
    visibility: hidden;
  }
  .narrow .side.open {
    transform: none;
    visibility: visible;
  }
  .narrow .side-item {
    height: 46px;
  }
  .narrow .scrim {
    display: block;
    position: absolute;
    inset: 0;
    z-index: 19;
    border: 0;
    padding: 0;
    background: rgba(5, 5, 6, 0.6);
  }
  .narrow .list,
  .narrow .detail {
    grid-column: 1;
    grid-row: 2;
    border-right: 0;
  }
  .narrow[data-pane="list"] .detail,
  .narrow[data-pane="detail"] .list {
    display: none;
  }
  .narrow .list {
    padding: 14px 14px 0;
  }
  .narrow .items {
    padding-bottom: calc(16px + env(safe-area-inset-bottom));
  }
  .narrow .item {
    padding: 12px;
  }
  .narrow .detail {
    padding: 20px 18px calc(28px + env(safe-area-inset-bottom));
  }
  .narrow .toast {
    left: 16px;
    right: 16px;
    top: auto;
    bottom: calc(16px + env(safe-area-inset-bottom));
    justify-content: center;
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
