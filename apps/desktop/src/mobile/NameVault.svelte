<script lang="ts">
  import Page from "./Page.svelte";
  import { createVault, errorMessage, renameVault, type VaultSummary } from "../lib/api";

  /** Creates a vault, or renames the one shown. */
  let {
    mode,
    vault,
    ondone,
  }: {
    mode: "new" | "rename";
    vault: VaultSummary | null;
    ondone: (vaults: VaultSummary[], id: string | null) => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let name = $state(mode === "rename" ? (vault?.name ?? "") : "");
  let busy = $state(false);
  let error = $state("");
  const trimmed = $derived(name.trim());
  const ready = $derived(trimmed.length > 0 && [...trimmed].length <= 64 && !busy);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    error = "";
    try {
      if (mode === "rename" && vault) {
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
</script>

<Page title={mode === "new" ? "New vault" : "Rename vault"} backLabel="Cancel">
  <p class="m-lede">Use vaults to keep things apart, like Family or Work. You can share a vault with others.</p>
  <form id="vault-form" onsubmit={submit}>
    <label class="m-label" for="vault-name">Name</label>
    <div class="m-field">
      <input id="vault-name" bind:value={name} maxlength="64" autocapitalize="words" disabled={busy} />
    </div>
    {#if error}<p class="m-error" role="alert">{error}</p>{/if}
  </form>
  {#snippet footer()}
    <button type="submit" form="vault-form" class="m-btn" disabled={!ready}>
      {mode === "new" ? "Create vault" : "Save"}
    </button>
  {/snippet}
</Page>
