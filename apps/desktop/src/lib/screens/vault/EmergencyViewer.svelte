<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import ItemDetail from "./ItemDetail.svelte";
  import {
    closeEmergency,
    errorMessage,
    listItems,
    type ItemSummary,
    type VaultSummary,
  } from "../../api";

  /** Another account's vaults, opened as its trusted contact. Read-only. */
  let {
    owner,
    vaults,
    onclose,
    onnotice,
  }: {
    owner: string;
    vaults: VaultSummary[];
    onclose: () => void;
    onnotice: (text: string) => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let vaultId = $state<string | null>(vaults[0]?.id ?? null);
  let items = $state<ItemSummary[]>([]);
  let selected = $state<string | null>(null);
  let error = $state("");
  let closing = $state(false);

  const vault = $derived(vaults.find((v) => v.id === vaultId) ?? null);

  $effect(() => {
    const id = vaultId;
    selected = null;
    items = [];
    if (!id) return;
    listItems(id, owner).then(
      (list) => {
        if (vaultId === id) items = list;
      },
      (e) => (error = errorMessage(e)),
    );
  });

  async function close() {
    if (closing) return;
    closing = true;
    try {
      await closeEmergency();
    } catch {
      // Closing only tidies up; the read-only session ends within a day.
    }
    onclose();
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Escape") close();
  }
</script>

<svelte:window {onkeydown} />

<div class="viewer" role="dialog" aria-modal="true" aria-labelledby="viewer-title">
  <header class="bar">
    <div class="title-line">
      <Icon name="key" size={16} />
      <span id="viewer-title">
        Emergency access to <span class="mono">{owner}</span> · read-only
      </span>
    </div>
    <button type="button" class="btn ghost sm" disabled={closing} onclick={close}>
      <Icon name="x" size={15} />Close
    </button>
  </header>

  {#if error}
    <p class="note" role="alert"><Icon name="alert" />{error}</p>
  {/if}

  <div class="layout">
    <nav class="side" aria-label="Their vaults">
      <div class="small group">Their vaults</div>
      {#each vaults as v (v.id)}
        <button
          type="button"
          class="side-item"
          class:on={v.id === vaultId}
          aria-current={v.id === vaultId ? "page" : undefined}
          onclick={() => (vaultId = v.id)}
        >
          <span class="side-name">{v.name}</span>
          <span class="count">{v.items}</span>
        </button>
      {:else}
        <p class="small">They have no vaults.</p>
      {/each}
    </nav>

    <section class="list" aria-label="Items">
      {#each items as it (it.id)}
        <button
          type="button"
          class="row"
          class:on={it.id === selected}
          onclick={() => (selected = it.id)}
        >
          <span class="avatar" aria-hidden="true">{it.title.slice(0, 1).toUpperCase()}</span>
          <span class="text">
            <span class="name">{it.title}</span>
            {#if it.subtitle}<span class="small">{it.subtitle}</span>{/if}
          </span>
        </button>
      {:else}
        <p class="small empty">No items in this vault.</p>
      {/each}
    </section>

    <main class="detail">
      {#if vault && selected}
        {#key selected}
          <ItemDetail
            {owner}
            vault={vault.id}
            vaultName={vault.name}
            itemId={selected}
            writable={false}
            onedit={() => {}}
            ondeleted={() => {}}
            {onnotice}
          />
        {/key}
      {:else}
        <p class="lede">
          Pick an item. Nothing here can be changed, and closing this deletes the copies from this
          computer.
        </p>
      {/if}
    </main>
  </div>
</div>

<style>
  .viewer {
    position: fixed;
    inset: 0;
    z-index: 20;
    background: var(--bg);
    display: flex;
    flex-direction: column;
  }
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 10px 24px;
    background: #2a1a0d;
    border-bottom: 1px solid var(--accent);
    color: #ffd9bf;
  }
  .title-line {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 14px;
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
    overflow-y: auto;
  }
  .group {
    padding: 0 10px 8px;
  }
  .side-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 9px 10px;
    border-radius: 8px;
    border: none;
    background: transparent;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }
  .side-item.on {
    background: var(--hover, rgba(255, 255, 255, 0.05));
  }
  .count {
    font-size: 12px;
    opacity: 0.6;
  }
  .list {
    border-right: 1px solid var(--hair);
    overflow-y: auto;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px;
    border-radius: 8px;
    border: none;
    background: transparent;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }
  .row.on {
    background: var(--hover, rgba(255, 255, 255, 0.05));
  }
  .avatar {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    display: grid;
    place-items: center;
    background: rgba(255, 106, 26, 0.12);
    color: var(--accent);
    flex: none;
  }
  .text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .empty {
    padding: 10px;
  }
  .detail {
    overflow-y: auto;
    padding: 32px 40px;
  }
</style>
