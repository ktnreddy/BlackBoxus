<script lang="ts">
  import Page from "./Page.svelte";
  import {
    conflictField,
    errorMessage,
    pendingChanges,
    resolveConflict,
    type Conflict,
  } from "../lib/api";

  /** Items changed both on this phone while offline and somewhere else.
   *  One at a time: the user picks a version, or keeps both. */
  let {
    onresolved,
    onnotice,
  }: { onresolved: (left: number) => void; onnotice: (text: string) => void } = $props();

  let list = $state<Conflict[]>([]);
  let keepMine = $state(true);
  let busy = $state(false);
  let error = $state("");
  /** Revealed values, keyed "mine:3" / "theirs:3", while held. */
  let shown = $state<Record<string, string>>({});

  const current = $derived(list[0] ?? null);

  pendingChanges().then(
    (p) => (list = p.conflicts),
    (e: unknown) => (error = errorMessage(e)),
  );

  const when = (ms: number) => {
    const d = new Date(ms);
    const today = new Date().toDateString() === d.toDateString();
    const time = d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }).toLowerCase();
    return today ? `today ${time}` : `${d.toLocaleDateString(undefined, { day: "numeric", month: "short" })}, ${time}`;
  };

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

  async function reveal(mine: boolean, index: number) {
    if (!current) return;
    try {
      const value = await conflictField(current.vault, current.item, mine, index);
      shown = { ...shown, [`${mine ? "mine" : "theirs"}:${index}`]: value };
    } catch (e) {
      error = errorMessage(e);
    }
  }
  function hide() {
    shown = {};
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
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<Page title={current ? `${current.title} was changed in two places` : "Changed in two places"} backLabel={current?.title ?? "Back"} tight small>
  <p class="m-lede">
    You edited it on this phone while offline, and it was also changed on another device. Pick the one
    to keep, or keep both.
  </p>
  {#if error}<p class="m-error" role="alert">{error}</p>{/if}

  {#if current}
    <div class="cf-group" role="radiogroup" aria-label="Version to keep">
      {#each [true, false] as mine (mine)}
        {@const v = mine ? current.mine : current.theirs}
        <button
          type="button"
          role="radio"
          class="cf-version"
          aria-checked={keepMine === mine}
          onclick={() => (keepMine = mine)}
        >
          <span class="cf-head">
            <span class="cf-radio" aria-hidden="true"><span></span></span>
            <span class="cf-who">
              <span class="cf-where">{mine ? "This phone" : "Another device"}</span>
              <span class="cf-when">
                {mine ? "Edited offline" : "Edited"}{v.changed_ms ? ` · ${when(v.changed_ms)}` : ""}
              </span>
            </span>
          </span>
          <span class="cf-fields">
            {#if v.deleted}
              <span class="cf-value">Deleted</span>
            {:else}
              {#each v.fields as f (f.index)}
                {@const key = `${mine ? "mine" : "theirs"}:${f.index}`}
                <span class="cf-field">
                  <span class="cf-label">{f.label || LABELS[f.kind] || "Field"}</span>
                  {#if f.concealed}
                    <span class="cf-secret">
                      <span class="cf-mono">{shown[key] ?? "•••••••••••••"}</span>
                      <span
                        class="cf-hold"
                        role="button"
                        tabindex="-1"
                        onpointerdown={(e) => {
                          e.stopPropagation();
                          reveal(mine, f.index);
                        }}
                        onpointerup={hide}
                        onpointerleave={hide}
                        onclick={(e) => e.stopPropagation()}
                        onkeydown={() => {}}
                      >Hold to show</span>
                    </span>
                  {:else}
                    <span class="cf-value">{f.value}</span>
                  {/if}
                </span>
              {/each}
            {/if}
          </span>
        </button>
      {/each}
    </div>
  {/if}

  {#snippet footer()}
    {#if current}
      <div class="cf-foot">
      <button type="button" class="m-fl-btn" disabled={busy} onclick={() => keep(keepMine ? "mine" : "theirs")}>
        {keepMine ? "Keep this phone's version" : "Keep the other version"}
      </button>
      {#if !current.mine.deleted}
        <button type="button" class="cf-both" disabled={busy} onclick={() => keep("both")}>Keep both as separate items</button>
      {/if}
      </div>
    {/if}
  {/snippet}
</Page>

<style>
  .cf-group {
    display: flex;
    flex-direction: column;
    gap: 12px;
    flex: none;
  }
  .cf-version {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 16px;
    border-radius: 20px;
    border: 1px solid #2a2a2e;
    background: #151517;
    color: #f4f4f5;
    font: inherit;
    text-align: left;
    box-sizing: content-box;
  }
  .cf-version[aria-checked="true"] {
    border: 2px solid #ff6a1a;
  }
  .cf-head {
    display: flex;
    align-items: center;
    gap: 12px;
    width: 100%;
  }
  .cf-radio {
    width: 22px;
    height: 22px;
    flex: none;
    box-sizing: border-box;
    border-radius: 11px;
    border: 2px solid #3f3f46;
    display: grid;
    place-items: center;
  }
  .cf-radio span {
    width: 10px;
    height: 10px;
    border-radius: 5px;
  }
  [aria-checked="true"] .cf-radio {
    border-color: #ff6a1a;
  }
  [aria-checked="true"] .cf-radio span {
    background: #ff6a1a;
  }
  .cf-who {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .cf-where {
    font-size: 16px;
    font-weight: 500;
  }
  .cf-when {
    font-size: 13px;
    color: #a1a1aa;
  }
  .cf-fields {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-left: 34px;
  }
  .cf-field {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .cf-label {
    font-size: 12px;
    color: #a1a1aa;
  }
  .cf-secret {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .cf-mono {
    font-family: var(--font-mono);
    font-size: 16px;
    word-break: break-all;
  }
  .cf-hold {
    font-size: 13px;
    color: #ffb27f;
    flex: none;
  }
  .cf-value {
    font-size: 15px;
    color: #d4d4d8;
    word-break: break-word;
  }
  .cf-foot {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .cf-both {
    width: 100%;
    min-height: 50px;
    border-radius: 25px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #f4f4f5;
    font: 500 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
</style>
