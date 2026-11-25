<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import NewPasswordFields from "../../components/NewPasswordFields.svelte";
  import PasswordField from "../../components/PasswordField.svelte";
  import { errorMessage, exportVaults } from "../../api";

  /** Exporting every vault: encrypted (the default) or as a plain CSV. */
  let {
    email,
    onclose,
    onnotice,
  }: { email: string; onclose: () => void; onnotice: (text: string) => void } = $props();

  let format = $state<"encrypted" | "csv">("encrypted");
  let master = $state("");
  let password = $state("");
  let confirm = $state("");
  let ok = $state(false);
  let understood = $state(false);
  let busy = $state(false);
  let error = $state("");

  const ready = $derived(master !== "" && (format === "encrypted" ? ok : understood));

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready || busy) return;
    busy = true;
    error = "";
    try {
      const done = await exportVaults(
        format === "encrypted" ? { format, master, password, confirm } : { format, master },
      );
      if (done) {
        const left = done.left_out > 0 ? ` ${done.left_out} left out: they need a newer app.` : "";
        onnotice(
          `Exported ${done.items} items from ${done.vaults} ${done.vaults === 1 ? "vault" : "vaults"}.${left}`,
        );
        onclose();
      }
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
  <div class="card accent" role="dialog" aria-modal="true" aria-labelledby="export-title">
  <form class="dialog" onsubmit={submit}>
    <div class="top">
      <h1 id="export-title" class="title">Export your vaults</h1>
      <button type="button" class="icon-btn" aria-label="Close" onclick={onclose} disabled={busy}>
        <Icon name="x" />
      </button>
    </div>
    <p class="lede">
      A copy of every vault you can open, in one file: a backup to keep, or a way to move to another
      account or app.
    </p>
    <div class="seg" role="radiogroup" aria-label="Format">
      <button type="button" aria-pressed={format === "encrypted"} onclick={() => (format = "encrypted")}>
        Encrypted (.bbx)
      </button>
      <button type="button" aria-pressed={format === "csv"} onclick={() => (format = "csv")}>Plain CSV</button>
    </div>
    <p class="small">
      {format === "encrypted"
        ? "Recommended. Locked with an export password you choose now; only BlackBoxus can open it."
        : "For moving to another password manager. Not encrypted: anyone with the file can read it."}
    </p>
    <PasswordField id="export-master" label="Your master password, to confirm it's you" bind:value={master} disabled={busy} />
    {#if format === "encrypted"}
      <NewPasswordFields {email} label="Export password" bind:password bind:confirm bind:ok disabled={busy} />
      <p class="small">
        Use a different password from your master password. Without it the file can't be opened, by
        anyone.
      </p>
    {:else}
      <label class="check">
        <input type="checkbox" bind:checked={understood} disabled={busy} />
        I understand this file isn't encrypted, and I'll delete it once I've used it.
      </label>
    {/if}
    {#if error}<p class="note" role="alert"><Icon name="alert" />{error}</p>{/if}
    <div class="row actions">
      <button type="button" class="btn ghost" onclick={onclose} disabled={busy}>Cancel</button>
      <button type="submit" class="btn primary" disabled={busy || !ready}>
        <Icon name="download" size={16} />{busy ? "Preparing…" : "Choose where to save it"}
      </button>
    </div>
  </form>
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
    width: min(600px, calc(100vw - 48px));
    max-height: calc(100vh - 48px);
    overflow-y: auto;
    padding: 32px 36px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    box-shadow: 0 50px 120px -40px rgba(0, 0, 0, 0.9);
  }
  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .title {
    margin: 0;
    font-size: 28px;
    font-weight: 300;
    letter-spacing: -0.02em;
  }
  .actions {
    justify-content: flex-end;
  }
  .seg {
    display: inline-flex;
    align-self: flex-start;
    padding: 4px;
    border-radius: 999px;
    background: #111113;
    border: 1px solid var(--line);
    gap: 2px;
  }
  .seg button {
    height: 34px;
    padding: 0 16px;
    border: 0;
    border-radius: 999px;
    background: transparent;
    color: var(--muted);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
  }
  .seg button[aria-pressed="true"] {
    background: var(--text);
    color: #111113;
  }
  .check {
    display: flex;
    gap: 10px;
    align-items: center;
    font-size: 14px;
  }
</style>
