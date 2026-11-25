<script lang="ts">
  import Icon from "./Icon.svelte";
  import Page from "./Page.svelte";
  import PasswordInput from "./PasswordInput.svelte";
  import NewPassword from "./NewPassword.svelte";
  import { back } from "./nav";
  import { errorMessage, exportVaults } from "../lib/api";

  /** Exporting every vault: encrypted (the default) or as a plain CSV. */
  let { email, onnotice }: { email: string; onnotice: (text: string) => void } = $props();

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
        master = password = confirm = "";
        const left = done.left_out > 0 ? ` ${done.left_out} left out: they need a newer app.` : "";
        onnotice(`Exported ${done.items} items from ${done.vaults} ${done.vaults === 1 ? "vault" : "vaults"}.${left}`);
        back();
      }
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<Page title="Export your vaults" backLabel="Settings" form>
  <p class="m-lede">
    A copy of every vault you can open, in one file: a backup to keep, or a way to move to another account
    or app.
  </p>
  <div class="ex-choice" role="radiogroup" aria-label="Format">
    <button type="button" role="radio" aria-checked={format === "encrypted"} class:on={format === "encrypted"} onclick={() => (format = "encrypted")}>
      <span class="ex-main">Encrypted (.bbx) · recommended</span>
      <span class="ex-sub">Locked with an export password you choose now. Only BlackBoxus can open it.</span>
    </button>
    <button type="button" role="radio" aria-checked={format === "csv"} class:on={format === "csv"} onclick={() => (format = "csv")}>
      <span class="ex-main">Plain CSV</span>
      <span class="ex-sub">For moving to another password manager. Not encrypted.</span>
    </button>
  </div>
  <form id="ex-form" class="ex-form" onsubmit={submit}>
    <PasswordInput id="ex-master" label="Your master password, to confirm it's you" bind:value={master} disabled={busy} />
    {#if format === "encrypted"}
      <NewPassword {email} bind:password bind:confirm bind:ok disabled={busy} label="Export password" />
      <p class="m-small">
        Use a different password from your master password, and keep it with the file's location. Without it
        the file can't be opened, by anyone.
      </p>
    {:else}
      <div class="m-note warn">
        <Icon name="alert" size={22} />
        <span>Anyone who gets the CSV can read every password in it. Import it right away, then delete it.</span>
      </div>
      <label class="ex-check">
        <input class="m-check" type="checkbox" bind:checked={understood} disabled={busy} />
        I understand this file isn't encrypted
      </label>
    {/if}
    {#if error}<p class="m-error" role="alert">{error}</p>{/if}
  </form>
  {#snippet footer()}
    <button type="submit" form="ex-form" class="m-fl-btn" disabled={busy || !ready}>
      {busy ? "Preparing the file…" : "Choose where to save it"}
    </button>
  {/snippet}
</Page>

<style>
  .ex-choice {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-bottom: 18px;
  }
  .ex-choice button {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 14px 16px;
    border-radius: 18px;
    border: 1px solid #1f1f22;
    background: #151517;
    color: #f4f4f5;
    text-align: left;
    font: 400 16px "DM Sans Variable", sans-serif;
  }
  .ex-choice button.on {
    border-color: rgba(255, 106, 26, 0.6);
    background: rgba(255, 106, 26, 0.08);
  }
  .ex-sub {
    font-size: 13px;
    color: #a1a1aa;
    line-height: 1.4;
  }
  .ex-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .ex-check {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 15px;
  }
</style>
