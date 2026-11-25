<script lang="ts">
  import Icon from "./Icon.svelte";
  import Page from "./Page.svelte";
  import { back } from "./nav";
  import {
    errorMessage,
    importChooseFile,
    importFinish,
    importProgress,
    importDuplicates,
    importOpenExport,
    importStart,
    type ImportPreview,
    type ImportProgress,
    type VaultSummary,
  } from "../lib/api";

  let { vaults, onnotice }: { vaults: VaultSummary[]; onnotice: (text: string) => void } = $props();

  const writable = $derived(vaults.filter((v) => v.writable));
  let step = $state<"choose" | "password" | "preview" | "running" | "done">("choose");
  /** The password of a BlackBoxus export, while it's being opened. */
  let exportPassword = $state("");
  /** The chosen file is a BlackBoxus export, encrypted. */
  let ownExport = $state(false);
  let fileName = $state("");
  let preview = $state<ImportPreview | null>(null);
  let target = $state("");
  let progress = $state<ImportProgress | null>(null);
  let busy = $state(false);
  let error = $state("");

  $effect(() => {
    if (!target) target = writable[0]?.id ?? "";
  });

  // Forget the chosen file when leaving before importing.
  $effect(() => () => {
    if (step !== "running") importFinish(false).catch(() => {});
  });

  async function choose() {
    busy = true;
    error = "";
    try {
      const chosen = await importChooseFile();
      if (chosen) {
        fileName = chosen.file_name;
        preview = chosen.preview;
        ownExport = chosen.needs_password;
        step = chosen.needs_password ? "password" : "preview";
      }
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function openExport(event: SubmitEvent) {
    event.preventDefault();
    if (!exportPassword) return;
    busy = true;
    error = "";
    const typed = exportPassword;
    try {
      preview = await importOpenExport(typed);
      exportPassword = "";
      step = "preview";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function start() {
    if (!target) return;
    busy = true;
    error = "";
    try {
      await importStart(target);
      step = "running";
      poll();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  function poll() {
    importProgress().then(
      (p) => {
        progress = p;
        if (p.running) setTimeout(poll, 500);
        else {
          step = "done";
          if (!p.error) onnotice(`Imported ${p.done} items.`);
        }
      },
      (e: unknown) => (error = errorMessage(e)),
    );
  }

  /** Items exactly like ones already in the chosen vault: left out. */
  let duplicates = $state(0);
  $effect(() => {
    const vault = target;
    const ready = preview !== null;
    duplicates = 0;
    if (!vault || !ready) return;
    importDuplicates(vault).then(
      (n) => {
        if (target === vault) duplicates = n;
      },
      () => {},
    );
  });
  const total = $derived(preview ? Math.max(0, preview.logins + preview.notes - duplicates) : 0);
  const tenths = $derived(
    progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 10) : 0,
  );
</script>

<Page title="Import passwords" backLabel="Settings">
  <p class="m-lede">
    Pick a CSV exported from your browser or old password manager, or a BlackBoxus export (.bbx) you made
    earlier.
  </p>
  {#if step === "password"}
    <form class="ip-form" onsubmit={openExport}>
      <p class="m-small">
        <strong>{fileName}</strong> is a BlackBoxus export. Type the export password chosen when it was made.
      </p>
      <label class="m-fl-field">
        <span class="m-fl-label">Export password</span>
        <span class="m-field"><input type="password" bind:value={exportPassword} autocomplete="off" disabled={busy} /></span>
      </label>
      <button type="submit" class="m-btn" disabled={busy || !exportPassword}>{busy ? "Opening… (a few seconds)" : "Open the export"}</button>
    </form>
  {/if}
  {#if step === "choose" || (step === "preview" && preview)}
    <button type="button" class="ip-pick" onclick={choose} disabled={busy}>
      <span class="ip-ic"><Icon name="file" size={22} /></span>
      {#if step === "preview" && preview}
        <span class="ip-grow"><span class="ip-main">{fileName}</span><span class="ip-sub">{preview.source} format</span></span>
        <span class="ip-change">Change</span>
      {:else}
        <span class="ip-grow"><span class="ip-main">Choose a CSV file</span><span class="ip-sub">Chrome, Firefox, Bitwarden, 1Password, LastPass and more</span></span>
      {/if}
    </button>
  {/if}
  {#if step === "preview" && preview}
    <div class="ip-list">
      <div class="ip-row"><span class="ip-label">Logins found</span><span class="ip-value">{preview.logins}</span></div>
      {#if preview.notes > 0}<div class="ip-row"><span class="ip-label">Notes found</span><span class="ip-value">{preview.notes}</span></div>{/if}
      {#if duplicates > 0}<div class="ip-row"><span class="ip-label">Already in your vault</span><span class="ip-value dim">{duplicates} skipped</span></div>{/if}
      {#if preview.skipped > 0}<div class="ip-row"><span class="ip-label">Rows we couldn't read</span><span class="ip-value bad">{preview.skipped}</span></div>{/if}
      <label class="ip-row last">
        <span class="ip-label">Put them in</span>
        <span class="ip-pickvault">{writable.find((v) => v.id === target)?.name ?? ""}<Icon name="down" size={16} /></span>
        <select class="ip-select" bind:value={target} aria-label="Put them in">
          {#each writable as v (v.id)}<option value={v.id}>{v.name}</option>{/each}
        </select>
      </label>
    </div>
    {#if !ownExport}
      <div class="ip-warn">
        <Icon name="alert" size={22} />
        <span>The CSV holds your passwords in plain text. Delete it from Downloads once the import finishes.</span>
      </div>
    {/if}
  {:else if step === "running" || step === "done"}
    <div class="m-list">
      <div class="m-row column">
        <span>{step === "done" ? "Finished" : "Importing…"} {progress?.done ?? 0} of {progress?.total ?? total}</span>
        <div class="bar" aria-hidden="true">
          {#each Array.from({ length: 10 }, (_, n) => n) as n (n)}<span class:on={tenths > n}></span>{/each}
        </div>
        {#if progress?.waiting_seconds}<span class="m-small">The server asked us to slow down. Carrying on in {progress.waiting_seconds}s.</span>{/if}
      </div>
    </div>
    {#if progress?.error}<p class="m-error" role="alert">{progress.error}</p>{/if}
    {#if step === "done" && !ownExport}
      <div class="m-note warn">
        <Icon name="alert" size={22} />
        <span>Now delete <strong>{fileName}</strong> in your Files app. It still holds your passwords in plain text.</span>
      </div>
    {/if}
  {/if}
  {#if error}<p class="m-error" role="alert">{error}</p>{/if}

  {#snippet footer()}
    {#if step === "preview"}
      <button type="button" class="m-fl-btn" onclick={start} disabled={busy || !target || total === 0}>
        Import {total} {total === 1 ? "item" : "items"}
      </button>
    {:else if step === "done"}
      <button type="button" class="m-fl-btn" onclick={() => importFinish(false).then(back, back)}>Done</button>
    {/if}
  {/snippet}
</Page>

<style>
  .ip-form {
    display: flex;
    flex-direction: column;
    gap: 14px;
    margin-bottom: 16px;
  }
  .ip-pick {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 16px;
    border-radius: 20px;
    border: 1px solid #2a2a2e;
    background: #151517;
    color: #f4f4f5;
    font: inherit;
    text-align: left;
    box-sizing: content-box;
    flex: none;
  }
  .ip-ic {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    background: rgba(255, 106, 26, 0.14);
    color: #ffb27f;
    display: grid;
    place-items: center;
    flex: none;
  }
  .ip-grow {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .ip-main {
    font-size: 16px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ip-sub {
    font-size: 13px;
    color: #a1a1aa;
  }
  .ip-change {
    font-size: 14px;
    color: #ffb27f;
  }
  .ip-list {
    background: #151517;
    border: 1px solid #1f1f22;
    border-radius: 20px;
    overflow: hidden;
    flex: none;
  }
  .ip-row {
    position: relative;
    display: flex;
    justify-content: space-between;
    align-items: center;
    min-height: 54px;
    padding: 0 18px;
    border-bottom: 1px solid #1f1f22;
  }
  .ip-row.last {
    border-bottom: 0;
  }
  .ip-label {
    flex: none;
    font-size: 15px;
    color: #d4d4d8;
  }
  .ip-value {
    font-size: 16px;
    font-weight: 500;
  }
  .ip-value.dim {
    color: #a1a1aa;
  }
  .ip-value.bad {
    color: #fca5a5;
  }
  .ip-pickvault {
    min-width: 0;
    padding-left: 12px;
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 16px;
    font-weight: 500;
  }
  .ip-pickvault :global(svg) {
    color: #a1a1aa;
  }
  .ip-select {
    position: absolute;
    inset: 0;
    width: 100%;
    opacity: 0;
  }
  .ip-warn {
    display: flex;
    gap: 12px;
    padding: 14px 16px;
    border-radius: 18px;
    background: rgba(255, 106, 26, 0.1);
    border: 1px solid rgba(255, 106, 26, 0.38);
    font-size: 14px;
    line-height: 1.45;
    color: #d4d4d8;
    flex: none;
  }
  .ip-warn > :global(svg) {
    flex: none;
    margin-top: 1px;
    color: #ffb27f;
  }
  .bar {
    display: grid;
    grid-template-columns: repeat(10, 1fr);
    gap: 3px;
  }
  .bar span {
    height: 6px;
    border-radius: 3px;
    background: #2a2a2e;
  }
  .bar span.on {
    background: #ff6a1a;
  }
  .column {
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
  }
</style>
