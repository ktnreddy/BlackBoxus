<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import { createVault, errorMessage, renameVault, type VaultSummary } from "../../api";

  /** Creates a vault, or renames one when `vault` is given. */
  let {
    vault = null,
    ondone,
    onclose,
  }: {
    vault?: VaultSummary | null;
    ondone: (vaults: VaultSummary[], id: string) => void;
    onclose: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let name = $state(vault?.name ?? "");
  let busy = $state(false);
  let error = $state("");

  const MAX = 64;
  const trimmed = $derived(name.trim());
  const ready = $derived(
    trimmed.length > 0 && [...trimmed].length <= MAX && trimmed !== vault?.name && !busy,
  );

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    error = "";
    try {
      if (vault) {
        ondone(await renameVault(vault.id, trimmed), vault.id);
      } else {
        const created = await createVault(trimmed);
        ondone(created.vaults, created.id);
      }
    } catch (e) {
      error = errorMessage(e);
      busy = false;
    }
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Escape" && !busy) onclose();
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop" role="presentation">
  <div class="card accent dialog" role="dialog" aria-modal="true" aria-labelledby="vault-name-title">
  <form class="form" onsubmit={submit}>
    <div class="top">
      <h1 id="vault-name-title" class="title">{vault ? "Rename vault" : "New vault"}</h1>
      <button type="button" class="icon-btn" aria-label="Close" onclick={onclose} disabled={busy}>
        <Icon name="x" />
      </button>
    </div>
    <p class="small">
      {#if vault}
        Everyone who can open this vault sees the new name.
      {:else}
        Keep different parts of your life apart, like work and home, and share a vault with the
        people who need it.
      {/if}
      The name is encrypted like everything else.
    </p>
    <div>
      <label class="label" for="vault-name">Name</label>
      <div class="field">
        <!-- svelte-ignore a11y_autofocus -->
        <input
          id="vault-name"
          type="text"
          bind:value={name}
          maxlength={MAX}
          autocomplete="off"
          spellcheck="false"
          autofocus
          disabled={busy}
        />
      </div>
    </div>
    {#if error}
      <p class="note" role="alert"><Icon name="alert" />{error}</p>
    {/if}
    <div class="row actions">
      <button type="button" class="btn ghost" onclick={onclose} disabled={busy}>Cancel</button>
      <button type="submit" class="btn primary" disabled={!ready}>
        {#if busy}{vault ? "Renaming…" : "Creating…"}{:else}{vault ? "Rename" : "Create vault"}{/if}
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
    width: min(480px, calc(100vw - 48px));
    padding: 28px 34px;
    box-shadow: 0 50px 120px -40px rgba(0, 0, 0, 0.9);
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: 18px;
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
  .small {
    margin: 0;
  }
  .actions {
    justify-content: flex-end;
    gap: 12px;
  }
</style>
