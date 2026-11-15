<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import {
    copyField,
    deleteItem,
    errorMessage,
    getItem,
    revealField,
    type ItemView,
  } from "../../api";

  let {
    vault,
    vaultName,
    itemId,
    writable,
    onedit,
    ondeleted,
    onnotice,
  }: {
    vault: string;
    vaultName: string;
    itemId: string;
    writable: boolean;
    onedit: (item: ItemView) => void;
    ondeleted: () => void;
    onnotice: (text: string) => void;
  } = $props();

  const LABELS: Record<string, string> = {
    username: "Username",
    password: "Password",
    url: "Website",
    notes: "Notes",
    totp: "One-time code secret",
    cardholder: "Name on card",
    card_number: "Card number",
    card_expiry: "Expiry date",
    card_code: "Security code",
    text: "Text",
    concealed: "Hidden text",
    title: "Title",
  };
  const TYPES: Record<string, string> = {
    login: "Login",
    note: "Secure note",
    card: "Card",
    identity: "Identity",
    api: "API credential",
  };

  let item = $state<ItemView | null>(null);
  let error = $state("");
  /** Revealed concealed values by field index, hidden again after a while. */
  let revealed = $state<Record<number, string>>({});
  let confirmDelete = $state(false);
  let deleting = $state(false);

  $effect(() => {
    const [v, id] = [vault, itemId];
    item = null;
    error = "";
    revealed = {};
    confirmDelete = false;
    getItem(v, id).then(
      (i) => (item = i),
      (e: unknown) => (error = errorMessage(e)),
    );
  });

  function label(f: { kind: string; label: string }): string {
    return f.label || LABELS[f.kind] || "Field";
  }

  const timers = new Map<number, ReturnType<typeof setTimeout>>();
  $effect(() => () => timers.forEach((t) => clearTimeout(t)));

  async function toggleReveal(index: number) {
    if (index in revealed) {
      const { [index]: _, ...rest } = revealed;
      revealed = rest;
      return;
    }
    try {
      const value = await revealField(vault, itemId, index);
      revealed = { ...revealed, [index]: value };
      clearTimeout(timers.get(index));
      // Hide it again after 30 seconds, like the clipboard.
      timers.set(
        index,
        setTimeout(() => {
          const { [index]: _, ...rest } = revealed;
          revealed = rest;
        }, 30_000),
      );
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  async function copy(index: number, concealed: boolean) {
    try {
      await copyField(vault, itemId, index);
      onnotice(concealed ? "Copied. The clipboard clears in 30 seconds." : "Copied.");
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  async function remove() {
    if (!confirmDelete) {
      confirmDelete = true;
      return;
    }
    deleting = true;
    try {
      await deleteItem(vault, itemId);
      ondeleted();
    } catch (e) {
      onnotice(errorMessage(e));
    } finally {
      deleting = false;
      confirmDelete = false;
    }
  }

  const changed = $derived(
    item
      ? new Date(item.modified_ms).toLocaleDateString(undefined, {
          day: "numeric",
          month: "short",
          year: "numeric",
        })
      : "",
  );
  const mainFields = $derived(
    item ? item.fields.map((f, i) => ({ f, i })).filter(({ f }) => f.kind !== "notes") : [],
  );
  const notes = $derived(
    item ? item.fields.map((f, i) => ({ f, i })).filter(({ f }) => f.kind === "notes") : [],
  );
</script>

{#if error}
  <p class="note" role="alert"><Icon name="alert" />{error}</p>
{:else if item}
  <header class="head">
    <div class="who">
      <span class="avatar" aria-hidden="true">{item.title.slice(0, 1).toUpperCase()}</span>
      <div>
        <h1 class="title selectable">{item.title}</h1>
        <span class="small">{TYPES[item.type] ?? "Item"} · {vaultName}</span>
      </div>
    </div>
    {#if writable}
      <button type="button" class="btn ghost sm" onclick={() => item && onedit(item)}>
        <Icon name="edit" size={15} />Edit
      </button>
    {/if}
  </header>

  {#if mainFields.length > 0}
    <dl class="card fields">
      {#each mainFields as { f, i } (i)}
        <div class="field-row">
          <div class="field-text">
            <dt class="small">{label(f)}</dt>
            <dd>
              {#if f.concealed}
                {#if i in revealed}
                  <span class="mono selectable">{revealed[i]}</span>
                {:else}
                  <span class="dots" aria-label="Hidden">••••••••••••••</span>
                {/if}
              {:else if f.kind === "url"}
                <span class="link-text selectable">{f.value}</span>
              {:else}
                <span class="selectable">{f.value}</span>
              {/if}
            </dd>
          </div>
          <div class="field-actions">
            {#if f.concealed}
              <button
                type="button"
                class="icon-btn"
                aria-label={i in revealed ? `Hide ${label(f)}` : `Show ${label(f)}`}
                aria-pressed={i in revealed}
                onclick={() => toggleReveal(i)}
              >
                <Icon name={i in revealed ? "eyeOff" : "eye"} />
              </button>
              <button type="button" class="btn primary sm" onclick={() => copy(i, true)}>
                <Icon name="copy" size={15} />Copy
              </button>
            {:else}
              <button
                type="button"
                class="icon-btn"
                aria-label={`Copy ${label(f)}`}
                onclick={() => copy(i, false)}
              >
                <Icon name="copy" />
              </button>
            {/if}
          </div>
        </div>
      {/each}
    </dl>
  {/if}

  {#each notes as { f, i } (i)}
    <div class="card notes">
      <div class="small">{label(f)}</div>
      <p class="selectable">{f.value}</p>
    </div>
  {/each}

  <footer class="foot">
    <span class="small">Changed {changed}</span>
    {#if writable}
      <button
        type="button"
        class="btn sm"
        class:ghost={!confirmDelete}
        class:danger={confirmDelete}
        disabled={deleting}
        onclick={remove}
        onblur={() => (confirmDelete = false)}
      >
        <Icon name="trash" size={15} />{confirmDelete ? "Delete for good?" : "Delete"}
      </button>
    {/if}
  </footer>
{/if}

<style>
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  .who {
    display: flex;
    align-items: center;
    gap: 16px;
    min-width: 0;
  }
  .avatar {
    width: 56px;
    height: 56px;
    border-radius: 18px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    font-weight: 500;
    flex: none;
  }
  .title {
    margin: 0;
    font-size: 36px;
    line-height: 1.1;
    font-weight: 300;
    letter-spacing: -0.03em;
    overflow-wrap: anywhere;
  }
  .fields {
    margin: 0;
  }
  .field-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 16px 24px;
    border-top: 1px solid var(--hair);
  }
  .field-row:first-child {
    border-top: 0;
  }
  .field-text {
    min-width: 0;
  }
  dd {
    margin: 4px 0 0;
    font-size: 16px;
    overflow-wrap: anywhere;
  }
  .dots {
    font-size: 20px;
    letter-spacing: 0.18em;
  }
  .link-text {
    color: var(--accent-soft);
  }
  .field-actions {
    display: flex;
    gap: 8px;
    flex: none;
  }
  .notes {
    padding: 16px 24px;
  }
  .notes p {
    margin: 4px 0 0;
    font-size: 15px;
    line-height: 1.5;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .foot {
    margin-top: auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .danger {
    background: #3a1414;
    border: 1px solid #6b2a2a;
    color: #ffc9c9;
  }
</style>
