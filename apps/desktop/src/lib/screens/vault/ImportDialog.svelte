<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import {
    errorMessage,
    importChooseFile,
    importFinish,
    importProgress,
    importStart,
    type ImportPreview,
    type ImportProgress,
    type VaultSummary,
  } from "../../api";

  let {
    vaults,
    current,
    onclose,
    ondone,
  }: {
    vaults: VaultSummary[];
    current: string | null;
    onclose: () => void;
    ondone: (vault: string) => void;
  } = $props();

  const writable = $derived(vaults.filter((v) => v.writable));
  let step = $state<"choose" | "preview" | "running" | "done">("choose");
  let fileName = $state("");
  let preview = $state<ImportPreview | null>(null);
  let target = $state<string>("");
  let progress = $state<ImportProgress | null>(null);
  let busy = $state(false);
  let error = $state("");
  let fileDeleted = $state(false);

  $effect(() => {
    if (!target) target = writable.find((v) => v.id === current)?.id ?? writable[0]?.id ?? "";
  });

  async function choose() {
    busy = true;
    error = "";
    try {
      const chosen = await importChooseFile();
      if (chosen) {
        fileName = chosen.file_name;
        preview = chosen.preview;
        step = "preview";
      }
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
    importProgress().then((p) => {
      progress = p;
      if (p.running) {
        setTimeout(poll, 500);
      } else {
        step = "done";
        ondone(target);
      }
    });
  }

  async function finish(deleteFile: boolean) {
    try {
      await importFinish(deleteFile);
      if (deleteFile) {
        fileDeleted = true;
        return;
      }
      onclose();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function cancel() {
    if (step === "running") return;
    try {
      await importFinish(false);
    } catch {
      // Nothing was chosen, or the vaults were locked; either way it's gone.
    }
    onclose();
  }

  const total = $derived(preview ? preview.logins + preview.notes : 0);
  const percent = $derived(
    progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 10) : 0,
  );

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Escape") cancel();
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop" role="presentation">
  <div class="card accent dialog" role="dialog" aria-modal="true" aria-labelledby="import-title">
    <div class="top">
      <h1 id="import-title" class="title">Import passwords</h1>
      {#if step !== "running"}
        <button type="button" class="icon-btn" aria-label="Close" onclick={cancel}>
          <Icon name="x" />
        </button>
      {/if}
    </div>

    {#if step === "choose"}
      <p class="lede">
        Export your passwords as a CSV file from your current password manager, then choose the file
        here. It's read on this computer and encrypted before anything is uploaded.
      </p>
      <p class="small">
        Works with exports from Bitwarden, 1Password, Chrome, Edge, Brave, Firefox, Safari, LastPass,
        KeePass, KeePassXC, Dashlane, NordPass and Proton Pass.
      </p>
      <div class="row actions">
        <button type="button" class="btn ghost" onclick={cancel}>Cancel</button>
        <button type="button" class="btn primary" disabled={busy} onclick={choose}>
          <Icon name="upload" size={16} />{busy ? "Reading…" : "Choose file"}
        </button>
      </div>
    {:else if step === "preview" && preview}
      <div class="summary">
        <div class="stat"><span class="num">{total}</span><span class="small">items</span></div>
        <div class="facts">
          <div><span class="small">File</span><span class="selectable">{fileName}</span></div>
          <div><span class="small">Looks like</span><span>{preview.source}</span></div>
          <div>
            <span class="small">Contains</span>
            <span
              >{preview.logins} {preview.logins === 1 ? "login" : "logins"}, {preview.notes}
              {preview.notes === 1 ? "note" : "notes"}{#if preview.skipped}, {preview.skipped} empty
                {preview.skipped === 1 ? "row" : "rows"} left out{/if}</span
            >
          </div>
          {#if preview.folders || preview.custom_fields}
            <div>
              <span class="small">Also kept</span>
              <span
                >{#if preview.folders}{preview.folders}
                  {preview.folders === 1 ? "folder" : "folders"}, as a Folder field{/if}{#if preview.folders && preview.custom_fields};
                {/if}{#if preview.custom_fields}{preview.custom_fields} custom
                  {preview.custom_fields === 1 ? "field" : "fields"}, hidden{/if}</span
              >
            </div>
          {/if}
        </div>
      </div>
      <div>
        <div class="small sample-label">First entries</div>
        <ul class="sample">
          {#each preview.sample as title, i (i)}<li>{title}</li>{/each}
        </ul>
      </div>
      {#if writable.length > 1}
        <div>
          <span class="label" id="target-label">Import into</span>
          <div class="seg" role="group" aria-labelledby="target-label">
            {#each writable as v (v.id)}
              <button type="button" aria-pressed={target === v.id} onclick={() => (target = v.id)}
                >{v.name}</button
              >
            {/each}
          </div>
        </div>
      {/if}
      <div class="row actions">
        <button type="button" class="btn ghost" onclick={cancel}>Cancel</button>
        <button type="button" class="btn primary" disabled={busy || !target} onclick={start}>
          Import {total} {total === 1 ? "item" : "items"}
        </button>
      </div>
    {:else if step === "running"}
      <p class="lede">
        Encrypting and saving {progress?.done ?? 0} of {progress?.total ?? total}…
      </p>
      <div class="bar" aria-hidden="true">
        {#each Array.from({ length: 10 }, (_, n) => n) as n (n)}<span class:on={n < percent}
          ></span>{/each}
      </div>
      {#if progress?.waiting_seconds}
        <p class="small">
          The server's limit was reached for now. Carrying on in about {Math.ceil(
            progress.waiting_seconds / 60,
          )}
          {Math.ceil(progress.waiting_seconds / 60) === 1 ? "minute" : "minutes"}; keep the app open.
        </p>
      {:else}
        <p class="small">Keep the app open until this finishes.</p>
      {/if}
    {:else if step === "done"}
      {#if progress?.error}
        <p class="note" role="alert">
          <Icon name="alert" />Stopped after {progress.done} of {progress.total}: {progress.error}
        </p>
      {:else}
        <p class="lede">
          Imported <span class="hi">{progress?.done ?? 0}</span>
          {progress?.done === 1 ? "item" : "items"}.
        </p>
      {/if}
      {#if fileDeleted}
        <p class="small">The export file was deleted.</p>
        <div class="row actions">
          <button type="button" class="btn primary" onclick={onclose}>Done</button>
        </div>
      {:else}
        <div class="note">
          <Icon name="alert" />
          <span
            >{fileName} still holds your passwords unencrypted. Delete it now, and empty the Recycle
            Bin if it goes there.</span
          >
        </div>
        <div class="row actions">
          <button type="button" class="btn ghost" onclick={() => finish(false)}>Keep the file</button>
          <button type="button" class="btn primary" onclick={() => finish(true)}>
            <Icon name="trash" size={16} />Delete the file
          </button>
        </div>
      {/if}
    {/if}

    {#if error}
      <p class="note" role="alert"><Icon name="alert" />{error}</p>
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
    width: min(600px, calc(100vw - 48px));
    padding: 32px 36px;
    display: flex;
    flex-direction: column;
    gap: 18px;
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
  .summary {
    display: flex;
    gap: 28px;
    align-items: center;
  }
  .stat {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
  }
  .num {
    font-size: 56px;
    font-weight: 300;
    letter-spacing: -0.04em;
    color: var(--accent);
    line-height: 1;
  }
  .facts {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  .facts div {
    display: flex;
    gap: 10px;
    align-items: baseline;
  }
  .facts .small {
    min-width: 76px;
  }
  .sample-label {
    margin-bottom: 6px;
  }
  .sample {
    list-style: none;
    margin: 0;
    padding: 12px 18px;
    border-radius: 16px;
    background: #0e0e10;
    border: 1px solid var(--line);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 14px;
  }
  .seg {
    display: inline-flex;
    padding: 4px;
    border-radius: 999px;
    background: #111113;
    border: 1px solid var(--line);
    gap: 2px;
    flex-wrap: wrap;
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
  .bar {
    display: grid;
    grid-template-columns: repeat(10, 1fr);
    gap: 3px;
  }
  .bar span {
    height: 6px;
    border-radius: 3px;
    background: var(--line);
  }
  .bar span.on {
    background: var(--accent);
  }
</style>
