<script lang="ts">
  import Icon from "./Icon.svelte";
  import { tint } from "./tint";
  import type { IconName } from "./icons";
  import type { GrantView, ItemSummary, ItemType, VaultSummary } from "../lib/api";

  let {
    vault,
    items,
    offline,
    syncing,
    unknownKeys,
    emergencyRequest,
    denying,
    waiting = 0,
    conflicts = 0,
    onconflicts,
    writable,
    onvaults,
    onitem,
    onmore,
    oncopy,
    onadd,
    onsync,
    ondeny,
    onlock,
  }: {
    vault: VaultSummary | null;
    items: ItemSummary[];
    offline: boolean;
    syncing: boolean;
    unknownKeys: boolean;
    emergencyRequest: GrantView | null;
    denying: boolean;
    writable: boolean;
    onvaults: () => void;
    onitem: (item: ItemSummary) => void;
    onmore: (item: ItemSummary) => void;
    oncopy: (item: ItemSummary) => void;
    onadd: () => void;
    onsync: () => void;
    ondeny: () => void;
    onlock: () => void;
    /** Changes made offline, still to be sent. */
    waiting?: number;
    /** Items changed both here and elsewhere. */
    conflicts?: number;
    onconflicts: () => void;
  } = $props();

  type Filter = "all" | "login" | "card" | "note" | "code";
  const FILTERS: { id: Filter; label: string }[] = [
    { id: "all", label: "All" },
    { id: "login", label: "Logins" },
    { id: "card", label: "Cards" },
    { id: "note", label: "Notes" },
    { id: "code", label: "Codes" },
  ];
  let filter = $state<Filter>("all");
  let query = $state("");

  const ICON: Partial<Record<ItemType, IconName>> = {
    note: "note",
    identity: "identity",
    api: "api",
  };

  const shown = $derived(
    [...items]
      .filter(
        (i) =>
          (filter === "all" || (filter === "code" ? i.has_code : i.type === filter)) &&
          (query.trim() === "" ||
            `${i.title} ${i.subtitle}`.toLowerCase().includes(query.trim().toLowerCase())),
      )
      .sort((a, b) => b.modified_ms - a.modified_ms),
  );

  // A long press opens the item's actions.
  let pressTimer: ReturnType<typeof setTimeout> | undefined;
  let pressed = false;
  function pressStart(item: ItemSummary) {
    pressed = false;
    clearTimeout(pressTimer);
    pressTimer = setTimeout(() => {
      pressed = true;
      onmore(item);
    }, 500);
  }
  function pressEnd() {
    clearTimeout(pressTimer);
  }
  function tap(item: ItemSummary) {
    if (pressed) {
      pressed = false;
      return;
    }
    onitem(item);
  }
</script>

<header class="top">
  <div class="bar">
    <button type="button" class="picker" aria-label="Switch vault" onclick={onvaults}>
      <img class="logo" src="/logo.png" alt="" />
      <span class="vname">{vault?.name ?? "Vaults"}</span>
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#a1a1aa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M0 0m6 9 6 6 6-6" /></svg>
    </button>
    <button type="button" class="lock" aria-label="Lock now" onclick={onlock}>
      <Icon name="lock" size={20} />
    </button>
  </div>
  <label class="search">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#a1a1aa" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M3 11a8 8 0 1 0 16 0a8 8 0 1 0 -16 0M0 0m21 21-4.3-4.3" /></svg>
    <span class="sr">Search this vault</span>
    <input
      class="q"
      type="search"
      placeholder={`Search ${items.length} ${items.length === 1 ? "item" : "items"}`}
      bind:value={query}
    />
  </label>
  <div class="chips" role="group" aria-label="Show">
    {#each FILTERS as f (f.id)}
      <button type="button" class="chip" class:on={filter === f.id} aria-pressed={filter === f.id} onclick={() => (filter = f.id)}>
        {f.label}
      </button>
    {/each}
  </div>
</header>

<main class="list">
  {#if offline}
    <div class="banner" role="status">
      <Icon name="offline" size={22} weight={1.8} />
      <span class="btext">
        <span class="bt">You're offline</span>
        <span class="bd">Everything still works. New and edited items are kept safe on this phone and sync by themselves when you're back online.{waiting > 0
            ? ` ${waiting} ${waiting === 1 ? "change" : "changes"} waiting.`
            : ""}
          <button type="button" class="again" onclick={onsync} disabled={syncing}>{syncing ? "Trying…" : "Try again"}</button></span>
      </span>
    </div>
  {/if}
  {#if conflicts > 0}
    <div class="banner" role="alert">
      <Icon name="alert" size={22} weight={1.8} />
      <span class="btext">
        <span class="bt">{conflicts === 1 ? "An item was" : `${conflicts} items were`} changed in two places</span>
        <span class="bd">Choose which version to keep.
          <button type="button" class="again" onclick={onconflicts}>Review</button></span>
      </span>
    </div>
  {/if}
  {#if emergencyRequest}
    <div class="banner" role="alert">
      <Icon name="alert" size={22} weight={1.8} />
      <span class="btext">
        <span class="bt">Your trusted contact asked for access</span>
        <span class="bd">If you do nothing, they can open your vaults in {emergencyRequest.wait_days} days.
          <button type="button" class="again" onclick={ondeny} disabled={denying}>Deny</button></span>
      </span>
    </div>
  {/if}
  {#if vault && vault.newer > 0}
    <div class="banner" role="status">
      <Icon name="alert" size={22} weight={1.8} />
      <span class="btext">
        <span class="bt">{vault.newer === 1 ? "1 item needs" : `${vault.newer} items need`} a newer BlackBoxus</span>
        <span class="bd">{vault.newer === 1 ? "It was" : "They were"} saved by a newer version on another device, and {vault.newer === 1 ? "is" : "are"} kept safe as {vault.newer === 1 ? "it is" : "they are"}. Update this app to see {vault.newer === 1 ? "it" : "them"}.</span>
      </span>
    </div>
  {/if}
  {#if unknownKeys}
    <div class="banner" role="alert">
      <Icon name="shieldAlert" size={22} weight={1.8} />
      <span class="btext">
        <span class="bt">A device key you didn't add</span>
        <span class="bd">If you didn't sign in on a new device, change your master password.</span>
      </span>
    </div>
  {/if}

  {#if shown.length > 0}
    <p class="label">{query.trim() ? "Matches" : "Recently changed"}</p>
    {#each shown as item (item.id)}
      <div
        class="row"
        role="button"
        tabindex="0"
        onclick={() => tap(item)}
        onkeydown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onitem(item);
          }
        }}
        onpointerdown={() => pressStart(item)}
        onpointerup={pressEnd}
        onpointerleave={pressEnd}
        oncontextmenu={(e) => {
          e.preventDefault();
          onmore(item);
        }}
      >
        <span class="badge {tint(item.title)}">
          {#if ICON[item.type]}
            <Icon name={ICON[item.type] ?? "note"} size={20} />
          {:else}
            {item.title[0]?.toUpperCase() ?? "?"}
          {/if}
        </span>
        <span class="text">
          <span class="title">{item.title}</span>
          <span class="sub">{item.subtitle}{item.has_code ? " · one-time code on" : ""}</span>
        </span>
        {#if item.pending}
          <span class="pend" class:bad={item.pending === "conflict"}>
            <Icon name={item.pending === "conflict" ? "alert" : "clock"} size={13} weight={2.2} />
            {item.pending === "new" ? "New" : item.pending === "edited" ? "Edited" : "Conflict"}
          </span>
        {/if}
        {#if item.type === "login" || item.type === "card"}
          <button
            type="button"
            class="copy"
            aria-label={item.type === "card" ? `Copy card number for ${item.title}` : `Copy password for ${item.title}`}
            onclick={(e) => {
              e.stopPropagation();
              oncopy(item);
            }}
            onpointerdown={(e) => e.stopPropagation()}
          >
            <Icon name="copy" size={20} />
          </button>
        {:else}
          <span class="copy" aria-hidden="true"></span>
        {/if}
      </div>
    {/each}
  {:else if !syncing}
    <div class="empty">
      {#if items.length === 0}
        <span class="ebadge"><Icon name="vault" size={30} /></span>
        <p class="etext">Nothing in {vault?.name ?? "this vault"} yet.</p>
        {#if writable}<button type="button" class="ebtn" onclick={onadd}>Add your first item</button>{/if}
      {:else}
        <p class="etext">No matches.</p>
      {/if}
    </div>
  {/if}
</main>

{#if writable}
  <button type="button" class="fab" aria-label="Add an item" onclick={onadd}>
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M5 12h14M12 5v14" /></svg>
  </button>
{/if}

<style>
  .top {
    padding: calc(52px + var(--sb)) 20px 12px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .picker {
    display: flex;
    align-items: center;
    gap: 10px;
    background: none;
    border: 0;
    padding: 0;
    color: #f4f4f5;
    font: inherit;
    min-width: 0;
  }
  .logo {
    width: 32px;
    height: 32px;
    border-radius: 9px;
  }
  .vname {
    font-size: 24px;
    font-weight: 500;
    letter-spacing: -0.02em;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .lock {
    width: 44px;
    height: 44px;
    border-radius: 22px;
    border: 1px solid #2a2a2e;
    background: #151517;
    display: grid;
    place-items: center;
    color: #d4d4d8;
  }
  .search {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 52px;
    padding: 0 16px;
    border-radius: 26px;
    background: #151517;
    border: 1px solid #2a2a2e;
  }
  .sr {
    position: absolute;
    left: -9999px;
  }
  .q {
    flex: 1;
    min-width: 0;
    background: none;
    border: 0;
    outline: none;
    color: #f4f4f5;
    font: 400 16px "DM Sans Variable", sans-serif;
    text-overflow: ellipsis;
  }
  .chips {
    display: flex;
    gap: 8px;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .chip {
    flex: none;
    min-height: 36px;
    padding: 0 16px;
    border-radius: 18px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #d4d4d8;
    font: 500 14px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .chip.on {
    border: 0;
    background: #ff6a1a;
    color: #140800;
  }
  .list {
    flex: 1;
    overflow-y: auto;
    /* Room below the last item, so the add button never covers its copy
       button. */
    padding: 4px 12px 88px;
    display: flex;
    flex-direction: column;
  }
  .list > * {
    flex-shrink: 0;
  }
  .label {
    margin: 8px 8px 6px;
    font-size: 13px;
    color: #a1a1aa;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 64px;
    padding: 8px;
    border-radius: 16px;
    color: #f4f4f5;
    -webkit-touch-callout: none;
    user-select: none;
  }
  .row:active {
    background: #151517;
  }
  .badge {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    background: #1c1c1f;
    display: grid;
    place-items: center;
    font-weight: 600;
    font-size: 17px;
    flex: none;
  }
  .text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .title {
    font-size: 16px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sub {
    font-size: 14px;
    color: #a1a1aa;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .pend {
    display: flex;
    align-items: center;
    gap: 5px;
    height: 26px;
    padding: 0 10px;
    flex: none;
    border-radius: 13px;
    background: #1c1c1f;
    font-size: 12px;
    color: #ffb27f;
  }
  .pend.bad {
    color: #fca5a5;
  }
  .copy {
    width: 40px;
    height: 40px;
    flex: none;
    border: 0;
    border-radius: 20px;
    background: none;
    display: grid;
    place-items: center;
    color: #a1a1aa;
  }
  button.copy:active {
    background: #1c1c1f;
    color: #f4f4f5;
  }
  .banner {
    margin: 0 4px 8px;
    display: flex;
    gap: 12px;
    padding: 14px 16px;
    border-radius: 18px;
    background: rgba(255, 106, 26, 0.1);
    border: 1px solid rgba(255, 106, 26, 0.38);
    color: #ffb27f;
  }
  .btext {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .bt {
    font-size: 15px;
    font-weight: 500;
    color: #f4f4f5;
  }
  .bd {
    font-size: 14px;
    line-height: 1.45;
    color: #d4d4d8;
  }
  .again {
    border: 0;
    background: none;
    margin-left: 4px;
    color: #ffb27f;
    font-weight: 500;
  }
  .empty {
    margin-top: 48px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
  }
  .ebadge {
    width: 64px;
    height: 64px;
    border-radius: 20px;
    background: #1c1c1f;
    color: #ffb27f;
    display: grid;
    place-items: center;
  }
  .etext {
    margin: 0;
    font-size: 16px;
    color: #d4d4d8;
  }
  .ebtn {
    min-height: 48px;
    padding: 0 22px;
    border-radius: 24px;
    border: 0;
    background: #ff6a1a;
    color: #140800;
    font: 600 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .fab {
    position: absolute;
    right: 20px;
    bottom: calc(100px + var(--bb));
    width: 60px;
    height: 60px;
    border: 0;
    border-radius: 20px;
    background: #ff6a1a;
    color: #140800;
    display: grid;
    place-items: center;
    box-shadow: 0 8px 24px rgba(255, 106, 26, 0.28);
  }
</style>
