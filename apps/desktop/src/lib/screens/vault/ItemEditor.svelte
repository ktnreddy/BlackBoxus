<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import GeneratorDialog from "./GeneratorDialog.svelte";
  import {
    errorMessage,
    revealField,
    saveItem,
    type ItemType,
    type ItemView,
  } from "../../api";

  let {
    vault,
    existing,
    onsaved,
    oncancel,
    onnotice,
  }: {
    vault: string;
    /** The item being edited, or null for a new one. */
    existing: ItemView | null;
    onsaved: (id: string) => void;
    oncancel: () => void;
    onnotice: (text: string) => void;
  } = $props();

  /** The field the generator fills, while it is open. */
  let generating = $state<string | null>(null);

  interface Spec {
    kind: string;
    label: string;
    concealed?: boolean;
    multiline?: boolean;
    placeholder?: string;
  }

  const FORMS: Record<"login" | "note" | "card", Spec[]> = {
    login: [
      { kind: "username", label: "Username or email" },
      { kind: "password", label: "Password", concealed: true },
      { kind: "url", label: "Website", placeholder: "https://" },
      { kind: "notes", label: "Notes", multiline: true },
    ],
    note: [{ kind: "notes", label: "Note", multiline: true }],
    card: [
      { kind: "cardholder", label: "Name on card" },
      { kind: "card_number", label: "Card number", concealed: true },
      { kind: "card_expiry", label: "Expiry date", placeholder: "MM/YY" },
      { kind: "card_code", label: "Security code", concealed: true },
      { kind: "notes", label: "Notes", multiline: true },
    ],
  };

  let type = $state<"login" | "note" | "card">("login");
  let title = $state("");
  let values = $state<Record<string, string>>({});
  /** Fields of the existing item that this form has no box for; kept as they are. */
  let extra = $state<{ kind: string; label: string; value: string }[]>([]);
  let shown = $state<Record<string, boolean>>({});
  let busy = $state(false);
  let loading = $state(false);
  let error = $state("");

  // Fill the form from the item being edited, fetching concealed values.
  $effect(() => {
    const item = existing;
    if (!item) return;
    loading = true;
    type = item.type === "note" || item.type === "card" ? item.type : "login";
    title = item.title;
    const formKinds = new Set(FORMS[type].map((s) => s.kind));
    Promise.all(
      item.fields.map(async (f, i) => ({
        f,
        value: f.concealed ? await revealField(vault, item.id, i) : (f.value ?? ""),
      })),
    ).then(
      (all) => {
        const filled: Record<string, string> = {};
        const rest: typeof extra = [];
        for (const { f, value } of all) {
          if (formKinds.has(f.kind) && !(f.kind in filled) && !f.label) filled[f.kind] = value;
          else rest.push({ kind: f.kind, label: f.label, value });
        }
        values = filled;
        extra = rest;
        loading = false;
      },
      (e: unknown) => {
        error = errorMessage(e);
        loading = false;
      },
    );
  });

  function useGenerated(kind: string, password: string) {
    values = { ...values, [kind]: password };
    shown = { ...shown, [kind]: true };
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !title.trim()) return;
    busy = true;
    error = "";
    try {
      const fields = [
        ...FORMS[type].map((s) => ({ kind: s.kind, label: "", value: values[s.kind] ?? "" })),
        ...extra,
      ];
      const id = await saveItem(vault, existing?.id ?? null, {
        type: existing && !(existing.type in FORMS) ? existing.type : (type as ItemType),
        title,
        fields,
      });
      values = {};
      onsaved(id);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<form class="editor" onsubmit={submit} aria-label={existing ? "Edit item" : "New item"}>
  <header class="head">
    <h1 class="title">{existing ? "Edit item" : "New item"}</h1>
    {#if !existing}
      <div class="seg" role="group" aria-label="Kind of item">
        {#each [["login", "Login"], ["note", "Secure note"], ["card", "Card"]] as [value, text] (value)}
          <button
            type="button"
            aria-pressed={type === value}
            onclick={() => (type = value as typeof type)}>{text}</button
          >
        {/each}
      </div>
    {/if}
  </header>

  <div class="card body">
    <div>
      <label class="label" for="item-title">Title</label>
      <div class="field">
        <input id="item-title" bind:value={title} autocomplete="off" disabled={busy || loading} />
      </div>
    </div>

    {#each FORMS[type] as spec (spec.kind)}
      <div>
        <label class="label" for={`item-${spec.kind}`}>{spec.label}</label>
        {#if spec.multiline}
          <textarea
            id={`item-${spec.kind}`}
            class="area"
            rows="3"
            bind:value={values[spec.kind]}
            disabled={busy || loading}
          ></textarea>
        {:else}
          <div class="field">
            <input
              id={`item-${spec.kind}`}
              class:mono={spec.concealed && shown[spec.kind]}
              type={spec.concealed && !shown[spec.kind] ? "password" : "text"}
              bind:value={values[spec.kind]}
              placeholder={spec.placeholder ?? ""}
              autocomplete="off"
              spellcheck="false"
              disabled={busy || loading}
            />
            {#if spec.concealed}
              <button
                type="button"
                class="icon-btn"
                aria-label={shown[spec.kind] ? `Hide ${spec.label}` : `Show ${spec.label}`}
                aria-pressed={!!shown[spec.kind]}
                onclick={() => (shown = { ...shown, [spec.kind]: !shown[spec.kind] })}
              >
                <Icon name={shown[spec.kind] ? "eyeOff" : "eye"} />
              </button>
            {/if}
            {#if spec.kind === "password"}
              <button type="button" class="btn ghost sm" onclick={() => (generating = spec.kind)}>
                <Icon name="wand" size={15} />Generate
              </button>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  </div>

  {#if error}
    <p class="note" role="alert"><Icon name="alert" />{error}</p>
  {/if}

  <div class="row actions">
    <button type="button" class="btn ghost" onclick={oncancel} disabled={busy}>Cancel</button>
    <button type="submit" class="btn primary" disabled={busy || loading || !title.trim()}>
      {busy ? "Saving…" : "Save"}
    </button>
  </div>
</form>

{#if generating}
  {@const kind = generating}
  <GeneratorDialog
    onuse={(password) => useGenerated(kind, password)}
    onclose={() => (generating = null)}
    {onnotice}
  />
{/if}

<style>
  .editor {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .title {
    margin: 0;
    font-size: 32px;
    font-weight: 300;
    letter-spacing: -0.03em;
  }
  .seg {
    display: inline-flex;
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
  .body {
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 18px;
  }
  .area {
    width: 100%;
    background: #111113;
    border: 1px solid var(--line);
    border-radius: 18px;
    padding: 14px 20px;
    font-size: 15px;
    line-height: 1.5;
    resize: vertical;
    outline: none;
  }
  .area:focus {
    border-color: var(--accent);
  }
  .actions {
    justify-content: flex-end;
  }
</style>
