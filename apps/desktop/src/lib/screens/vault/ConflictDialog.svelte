<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import {
    conflictField,
    errorMessage,
    pendingChanges,
    resolveConflict,
    type Conflict,
  } from "../../api";

  /** Items changed on this computer while offline and also elsewhere.
   *  One at a time: keep one version, or both as separate items. */
  let {
    onresolved,
    onclose,
    onnotice,
  }: {
    onresolved: (left: number) => void;
    onclose: () => void;
    onnotice: (text: string) => void;
  } = $props();

  let list = $state<Conflict[]>([]);
  let keepMine = $state(true);
  let busy = $state(false);
  let error = $state("");
  /** Revealed values, keyed "mine:3" or "theirs:3". */
  let shown = $state<Record<string, string>>({});

  const current = $derived(list[0] ?? null);

  pendingChanges().then(
    (p) => (list = p.conflicts),
    (e: unknown) => (error = errorMessage(e)),
  );

  const LABELS: Record<string, string> = {
    username: "Username",
    password: "Password",
    url: "Website",
    notes: "Notes",
    totp: "One-time code",
    cardholder: "Name on card",
    card_number: "Card number",
    card_expiry: "Expiry",
    card_code: "Security code",
  };

  const when = (ms: number) =>
    new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

  async function toggle(mine: boolean, index: number) {
    if (!current) return;
    const key = `${mine ? "mine" : "theirs"}:${index}`;
    if (key in shown) {
      const { [key]: _, ...rest } = shown;
      shown = rest;
      return;
    }
    try {
      shown = { ...shown, [key]: await conflictField(current.vault, current.item, mine, index) };
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function keep(choice: "mine" | "theirs" | "both") {
    if (!current || busy) return;
    busy = true;
    error = "";
    try {
      await resolveConflict(current.vault, current.item, choice);
      list = list.slice(1);
      keepMine = true;
      shown = {};
      onnotice(choice === "both" ? "Kept both as separate items." : "Saved and synced.");
      onresolved(list.length);
      if (list.length === 0) onclose();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Escape" && !busy) onclose();
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop" role="presentation">
  <div class="card accent dialog" role="dialog" aria-modal="true" aria-labelledby="conflict-title">
    <div class="top">
      <h1 id="conflict-title" class="title">
        {current ? `${current.title} was changed in two places` : "Changed in two places"}
      </h1>
      <button type="button" class="icon-btn" aria-label="Close" onclick={onclose} disabled={busy}>
        <Icon name="x" />
      </button>
    </div>
    <p class="small">
      You edited it on this computer while offline, and it was also changed on another device. Keep
      one version, or keep both as separate items.
    </p>
    {#if list.length > 1}<p class="small">{list.length} items to check.</p>{/if}

    {#if current}
      <div class="versions" role="radiogroup" aria-label="Version to keep">
        {#each [true, false] as mine (mine)}
          {@const v = mine ? current.mine : current.theirs}
          <button
            type="button"
            role="radio"
            class="version"
            aria-checked={keepMine === mine}
            onclick={() => (keepMine = mine)}
          >
            <span class="head">
              <span class="radio" aria-hidden="true"></span>
              <span class="who">
                <span class="where">{mine ? "This computer" : "Another device"}</span>
                <span class="small">{mine ? "Edited offline" : "Edited"}{v.changed_ms ? ` · ${when(v.changed_ms)}` : ""}</span>
              </span>
            </span>
            <span class="fields">
              {#if v.deleted}
                <span class="value">Deleted</span>
              {:else}
                {#each v.fields as f (f.index)}
                  {@const key = `${mine ? "mine" : "theirs"}:${f.index}`}
                  <span class="f">
                    <span class="small">{f.label || LABELS[f.kind] || "Field"}</span>
                    {#if f.concealed}
                      <span class="secret">
                        <span class="mono">{shown[key] ?? "•••••••••••••"}</span>
                        <span
                          class="reveal"
                          role="button"
                          tabindex="0"
                          onclick={(e) => {
                            e.stopPropagation();
                            toggle(mine, f.index);
                          }}
                          onkeydown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              e.stopPropagation();
                              toggle(mine, f.index);
                            }
                          }}>{key in shown ? "Hide" : "Show"}</span
                        >
                      </span>
                    {:else}
                      <span class="value">{f.value}</span>
                    {/if}
                  </span>
                {/each}
              {/if}
            </span>
          </button>
        {/each}
      </div>
    {/if}

    {#if error}<p class="note" role="alert"><Icon name="alert" />{error}</p>{/if}

    {#if current}
      <div class="row actions">
        {#if !current.mine.deleted}
          <button type="button" class="btn ghost" disabled={busy} onclick={() => keep("both")}>Keep both</button>
        {/if}
        <button type="button" class="btn primary" disabled={busy} onclick={() => keep(keepMine ? "mine" : "theirs")}>
          {keepMine ? "Keep this computer's version" : "Keep the other version"}
        </button>
      </div>
    {/if}
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(5, 5, 6, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
  }
  .dialog {
    width: min(560px, calc(100vw - 48px));
    max-height: calc(100vh - 48px);
    overflow-y: auto;
    padding: 28px 34px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    box-shadow: 0 50px 120px -40px rgba(0, 0, 0, 0.9);
  }
  .top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
  }
  .title {
    margin: 0;
    font-size: 26px;
    line-height: 1.2;
    font-weight: 300;
    letter-spacing: -0.02em;
  }
  .small {
    margin: 0;
  }
  .versions {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .version {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 16px;
    border-radius: 18px;
    border: 1px solid var(--line);
    background: var(--panel);
    color: var(--text);
    text-align: left;
    font: inherit;
    cursor: pointer;
  }
  .version[aria-checked="true"] {
    border-color: var(--accent);
    box-shadow: inset 0 0 0 1px var(--accent);
  }
  .head {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .radio {
    width: 20px;
    height: 20px;
    flex: none;
    border-radius: 50%;
    border: 2px solid #52525b;
  }
  [aria-checked="true"] .radio {
    border-color: var(--accent);
    background: radial-gradient(circle, var(--accent) 0 4px, transparent 4.5px);
  }
  .who {
    display: flex;
    flex-direction: column;
  }
  .where {
    font-weight: 500;
  }
  .fields {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-left: 32px;
  }
  .f {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .secret {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .mono {
    font-family: var(--font-mono);
    word-break: break-all;
  }
  .reveal {
    color: var(--accent-soft);
    font-size: 13px;
    cursor: pointer;
  }
  .value {
    overflow-wrap: anywhere;
  }
  .actions {
    justify-content: flex-end;
    gap: 12px;
    flex-wrap: wrap;
  }
</style>
