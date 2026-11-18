<script lang="ts">
  import Icon from "./Icon.svelte";
  import Sheet from "./Sheet.svelte";
  import ScanOverlay from "./ScanOverlay.svelte";
  import { back, opened } from "./nav";
  import { ICONS } from "./icons";
  import {
    errorMessage,
    generatePassword,
    ratePassword,
    revealField,
    saveItem,
    type ItemType,
    type ItemView,
    type Rating,
    type VaultSummary,
  } from "../lib/api";

  let {
    vault,
    vaults,
    existing,
    type: initialType,
    onsaved,
  }: {
    vault: VaultSummary;
    vaults: VaultSummary[];
    /** The item being edited, or null for a new one. */
    existing: ItemView | null;
    type: "login" | "note" | "card";
    onsaved: (id: string, vault: string) => void;
  } = $props();

  type Kind = "login" | "note" | "card";
  interface Spec {
    kind: string;
    label: string;
    concealed?: boolean;
    multiline?: boolean;
    placeholder?: string;
    input?: "email" | "url" | "numeric" | "text";
    /** Hidden behind an "add" row until used. */
    optional?: boolean;
  }

  const FORMS: Record<Kind, Spec[]> = {
    login: [
      { kind: "username", label: "Username or email", input: "email" },
      { kind: "password", label: "Password", concealed: true },
      { kind: "url", label: "Website", input: "url" },
      { kind: "totp", label: "One-time code secret", concealed: true, placeholder: "Setup key or otpauth:// link", optional: true },
      { kind: "notes", label: "Notes", multiline: true, optional: true },
    ],
    note: [{ kind: "notes", label: "Note", multiline: true }],
    card: [
      { kind: "cardholder", label: "Name on card" },
      { kind: "card_number", label: "Card number", concealed: true, input: "numeric" },
      { kind: "card_expiry", label: "Expiry date", placeholder: "MM/YY", input: "numeric" },
      { kind: "card_code", label: "Security code", concealed: true, input: "numeric" },
      { kind: "notes", label: "Notes", multiline: true, optional: true },
    ],
  };
  const TYPES: { id: Kind; label: string }[] = [
    { id: "login", label: "Login" },
    { id: "card", label: "Card" },
    { id: "note", label: "Secure note" },
  ];
  const NAMES: Record<Kind, string> = { login: "login", card: "card", note: "secure note" };

  // svelte-ignore state_referenced_locally
  let type = $state<Kind>(initialType);
  // svelte-ignore state_referenced_locally
  let target = $state(vault);
  const specs = $derived(FORMS[type]);
  // svelte-ignore state_referenced_locally
  let title = $state(existing?.title ?? "");
  let values = $state<Record<string, string>>({});
  let extra = $state<{ kind: string; label: string; value: string }[]>([]);
  let shown = $state<Record<string, boolean>>({});
  /** Optional fields the user has opened. */
  let added = $state<Record<string, boolean>>({});
  let busy = $state(false);
  // svelte-ignore state_referenced_locally
  let loading = $state(existing !== null);
  let error = $state("");
  let choosing = $state(false);

  $effect(() => {
    const item = existing;
    if (!item) return;
    const kinds = new Set(FORMS[initialType].map((s) => s.kind));
    Promise.all(
      item.fields.map(async (f, i) => ({
        f,
        value: f.concealed ? await revealField(vault.id, item.id, i) : (f.value ?? ""),
      })),
    ).then(
      (all) => {
        const filled: Record<string, string> = {};
        const rest: typeof extra = [];
        for (const { f, value } of all) {
          if (kinds.has(f.kind) && !(f.kind in filled) && !f.label) filled[f.kind] = value;
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

  /** Scanning a one-time code's QR code with the camera. */
  let scanning = $state(false);
  function startScan() {
    added = { ...added, totp: true };
    scanning = true;
  }

  /** Labels for fields the form has no row of its own for. */
  const KIND_LABELS: Record<string, string> = {
    username: "Username",
    password: "Password",
    url: "Website",
    notes: "Notes",
    totp: "One-time code secret",
    cardholder: "Name on card",
    card_number: "Card number",
    card_expiry: "Expiry",
    card_code: "Security code",
  };
  /** Custom fields can be renamed and hidden; others keep their kind. */
  const custom = (kind: string) => kind === "text" || kind === "concealed";
  function addCustom() {
    extra = [...extra, { kind: "text", label: "", value: "" }];
    // Focus the new field's name once it's on screen.
    setTimeout(() => document.getElementById(`x-label-${extra.length - 1}`)?.focus(), 0);
  }

  const visible = (s: Spec) => !s.optional || added[s.kind] || (values[s.kind] ?? "") !== "";

  // Rate the password as it's typed.
  let rating = $state<Rating | null>(null);
  $effect(() => {
    const pw = values.password ?? "";
    if (type !== "login" || pw === "") {
      rating = null;
      return;
    }
    const timer = setTimeout(() => {
      ratePassword(pw, "").then(
        (r) => (rating = r),
        () => (rating = null),
      );
    }, 150);
    return () => clearTimeout(timer);
  });

  async function generate() {
    try {
      const made = await generatePassword({
        kind: "passphrase",
        words: 4,
        separator: "-",
        capitalise: false,
        number: true,
      });
      values = { ...values, password: made.password };
      shown = { ...shown, password: true };
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function save() {
    if (busy || loading || !title.trim()) return;
    busy = true;
    error = "";
    try {
      const fields = [
        ...specs.map((s) => ({ kind: s.kind, label: "", value: values[s.kind] ?? "" })),
        ...extra,
      ];
      const id = await saveItem(target.id, existing?.id ?? null, {
        type: existing && !(existing.type in FORMS) ? existing.type : (type as ItemType),
        title: title.trim(),
        // A custom field needs a name; one left empty gets a plain one.
        fields: fields
          .filter((f) => !custom(f.kind) || f.label.trim() !== "" || f.value !== "")
          .map((f) => (custom(f.kind) && f.label.trim() === "" ? { ...f, label: "Field" } : f)),
      });
      values = {};
      onsaved(id, target.id);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  const writable = $derived(vaults.filter((v) => v.writable));
  const meterClass = $derived(
    rating === null ? "" : rating.score >= 4 ? "good" : rating.score <= 1 ? "weak" : "",
  );
</script>

<div class="screen">
  <header class="head">
    <button type="button" class="close" aria-label="Close" onclick={back} disabled={busy}><Icon name="x" size={22} /></button>
    <span class="title">{existing ? `Edit ${NAMES[type]}` : `New ${NAMES[type]}`}</span>
    <button type="button" class="save" onclick={save} disabled={busy || loading || !title.trim()}>{busy ? "Saving…" : "Save"}</button>
  </header>

  {#if !existing}
    <div class="types" role="radiogroup" aria-label="Item type">
      {#each TYPES as t (t.id)}
        <button type="button" role="radio" class="type" class:on={type === t.id} aria-checked={type === t.id} onclick={() => (type = t.id)}>{t.label}</button>
      {/each}
    </div>
  {/if}

  <main class="form">
    <label class="fld">
      <span class="lbl">Name</span>
      <input class="inp" bind:value={title} disabled={busy || loading} autocapitalize="words" />
    </label>

    {#each specs.filter(visible) as s (s.kind)}
      {#if s.kind === "password"}
        <div class="fld">
          <label class="lbl" for="f-password">Password</label>
          <div class="wrap">
            <input
              id="f-password"
              class="pin"
              type={shown.password ? "text" : "password"}
              bind:value={values.password}
              disabled={busy || loading}
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
            />
            <button type="button" class="gen" aria-label="Make a new password" onclick={generate} disabled={busy || loading}>
              <Icon name="refresh" size={20} />
            </button>
          </div>
          {#if rating}
            <div class="meter" class:good={rating.score >= 4} class:weak={rating.score <= 1}>
              <div class="bars" aria-hidden="true">
                {#each [1, 2, 3, 4] as n (n)}<span class:on={rating.score >= n}></span>{/each}
              </div>
              <span class="what">{rating.label}</span>
            </div>
          {/if}
        </div>
      {:else if s.multiline}
        <label class="fld">
          <span class="lbl">{s.label}</span>
          <textarea class="inp area" rows="4" bind:value={values[s.kind]} disabled={busy || loading}></textarea>
        </label>
      {:else if s.concealed}
        <div class="fld">
          <label class="lbl" for={`f-${s.kind}`}>{s.label}</label>
          <div class="wrap">
            <input
              id={`f-${s.kind}`}
              class="pin"
              type={shown[s.kind] ? "text" : "password"}
              inputmode={s.input === "numeric" ? "numeric" : "text"}
              placeholder={s.placeholder ?? ""}
              bind:value={values[s.kind]}
              disabled={busy || loading}
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
            />
            {#if s.kind === "totp"}
              <button type="button" class="gen plain" aria-label="Scan the QR code" onclick={startScan} disabled={busy || loading}>
                <Icon name="scan" size={20} />
              </button>
            {/if}
            <button
              type="button"
              class="gen plain"
              aria-label={shown[s.kind] ? `Hide ${s.label}` : `Show ${s.label}`}
              aria-pressed={shown[s.kind] ?? false}
              onclick={() => (shown = { ...shown, [s.kind]: !shown[s.kind] })}
            >
              <Icon name={shown[s.kind] ? "eyeOff" : "eye"} size={20} />
            </button>
          </div>
        </div>
      {:else}
        <label class="fld">
          <span class="lbl">{s.label}</span>
          <input
            class="inp"
            inputmode={s.input === "email" ? "email" : s.input === "url" ? "url" : s.input === "numeric" ? "numeric" : "text"}
            placeholder={s.placeholder ?? ""}
            bind:value={values[s.kind]}
            disabled={busy || loading}
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
          />
        </label>
      {/if}
    {/each}

    {#each extra as x, j (j)}
      <div class="fld">
        <div class="xhead">
          {#if custom(x.kind)}
            <input
              id={`x-label-${j}`}
              class="xlabel"
              placeholder="Field name"
              aria-label="Field name"
              bind:value={x.label}
              disabled={busy || loading}
              autocapitalize="sentences"
            />
            <label class="xhide">
              Hidden
              <input
                class="m-switch"
                type="checkbox"
                role="switch"
                checked={x.kind === "concealed"}
                disabled={busy || loading}
                onchange={(e) => (x.kind = (e.currentTarget as HTMLInputElement).checked ? "concealed" : "text")}
              />
            </label>
          {:else}
            <span class="lbl">{x.label || KIND_LABELS[x.kind] || "Field"}</span>
          {/if}
          <button
            type="button"
            class="xremove"
            aria-label={`Remove ${x.label || KIND_LABELS[x.kind] || "field"}`}
            disabled={busy || loading}
            onclick={() => (extra = extra.filter((_, k) => k !== j))}
          >
            <Icon name="x" size={18} />
          </button>
        </div>
        {#if x.kind === "notes"}
          <textarea class="inp area" rows="3" bind:value={x.value} disabled={busy || loading} aria-label={x.label || "Notes"}></textarea>
        {:else}
          <div class="wrap">
            <input
              class="pin"
              class:plainfont={x.kind !== "concealed"}
              type={x.kind === "concealed" || x.kind === "password" || x.kind === "card_number" || x.kind === "card_code" || x.kind === "totp" ? (shown[`x${j}`] ? "text" : "password") : "text"}
              bind:value={x.value}
              disabled={busy || loading}
              aria-label={x.label || KIND_LABELS[x.kind] || "Field"}
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
            />
            {#if x.kind === "concealed" || x.kind === "password" || x.kind === "card_number" || x.kind === "card_code" || x.kind === "totp"}
              <button
                type="button"
                class="gen plain"
                aria-label={shown[`x${j}`] ? "Hide" : "Show"}
                aria-pressed={shown[`x${j}`] ?? false}
                onclick={() => (shown = { ...shown, [`x${j}`]: !shown[`x${j}`] })}
              >
                <Icon name={shown[`x${j}`] ? "eyeOff" : "eye"} size={20} />
              </button>
            {/if}
          </div>
        {/if}
      </div>
    {/each}

    <div class="adds">
        {#each specs.filter((s) => !visible(s)) as s (s.kind)}
          <button type="button" class="add" onclick={() => (s.kind === "totp" ? startScan() : (added = { ...added, [s.kind]: true }))}>
            {#if s.kind === "totp"}
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffb27f" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12a10 10 0 1 0 20 0a10 10 0 1 0 -20 0M12 6v6l4 2" /></svg>
              <span class="atext">Add one-time code</span>
              <span class="ahint">Scan QR</span>
            {:else}
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffb27f" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M5 12h14M12 5v14" /></svg>
              <span class="atext">Add note</span>
            {/if}
          </button>
        {/each}
        <button type="button" class="add" onclick={addCustom} disabled={busy || loading}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffb27f" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M5 12h14M12 5v14" /></svg>
          <span class="atext">Add custom field</span>
          <span class="ahint">PIN, account number…</span>
        </button>
      </div>
    {#if error}<p class="err" role="alert">{error}</p>{/if}
  </main>

  <div class="foot">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={ICONS.vault} /></svg>
    <span class="fto">Saving to <strong class="to">{target.name}</strong></span>
    {#if !existing && writable.length > 1}
      <button
        type="button"
        class="change"
        onclick={() => {
          choosing = true;
          opened(() => (choosing = false));
        }}>Change</button
      >
    {/if}
  </div>
</div>

{#if scanning}
  <ScanOverlay
    onscanned={(text) => {
      scanning = false;
      values = { ...values, totp: text.trim() };
    }}
    onclose={(why) => {
      scanning = false;
      if (why) error = why;
    }}
  />
{/if}

{#if choosing}
  <Sheet label="Save to">
    <h2 class="sh-title">Save to</h2>
    {#each writable as v (v.id)}
      <button
        type="button"
        class="vrow"
        class:current={v.id === target.id}
        onclick={() => {
          target = v;
          back();
        }}
      >
        <span class="vbadge">{v.name[0]?.toUpperCase() ?? "?"}</span>
        <span class="vname">{v.name}</span>
        {#if v.id === target.id}
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ff6a1a" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5" /></svg>
        {/if}
      </button>
    {/each}
  </Sheet>
{/if}

<style>
  .screen {
    position: fixed;
    inset: 0;
    z-index: 20;
    background: #0b0b0c;
    color: #f4f4f5;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .head {
    padding: calc(48px + var(--sb)) 12px 8px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .close {
    width: 44px;
    height: 44px;
    border: 0;
    border-radius: 22px;
    background: none;
    display: grid;
    place-items: center;
    color: #f4f4f5;
  }
  .title {
    font-size: 17px;
    font-weight: 500;
  }
  .save {
    min-height: 44px;
    padding: 0 20px;
    border: 0;
    border-radius: 22px;
    background: #ff6a1a;
    color: #140800;
    display: flex;
    align-items: center;
    font-size: 15px;
    font-weight: 600;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .save:disabled {
    opacity: 0.45;
  }
  .types {
    display: flex;
    gap: 8px;
    padding: 12px 16px 4px;
    /* With large text the chips scroll sideways rather than squeeze. */
    overflow-x: auto;
    scrollbar-width: none;
  }
  .types > * {
    flex: none;
  }
  .type {
    min-height: 40px;
    padding: 0 16px;
    border-radius: 20px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #d4d4d8;
    font: 500 14px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .type.on {
    border: 0;
    background: #ff6a1a;
    color: #140800;
  }
  .form {
    flex: 1;
    padding: 12px 16px 16px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    overflow-y: auto;
  }
  .form > * {
    flex-shrink: 0;
  }
  .fld {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .lbl {
    font-size: 14px;
    color: #a1a1aa;
    padding-left: 4px;
  }
  .inp {
    height: 56px;
    padding: 0 16px;
    border-radius: 16px;
    border: 1px solid #2a2a2e;
    background: #151517;
    color: #f4f4f5;
    font: 400 17px "DM Sans Variable", sans-serif;
    outline: none;
  }
  .inp:focus {
    border: 2px solid #ff6a1a;
  }
  .area {
    height: auto;
    padding: 14px 16px;
    resize: none;
    line-height: 1.45;
  }
  .wrap {
    display: flex;
    align-items: center;
    gap: 4px;
    height: 56px;
    box-sizing: border-box;
    padding: 0 6px 0 16px;
    border-radius: 16px;
    border: 1px solid #2a2a2e;
    background: #151517;
  }
  .wrap:focus-within {
    border: 2px solid #ff6a1a;
    padding: 0 5px 0 15px;
  }
  .pin {
    flex: 1;
    min-width: 0;
    background: none;
    border: 0;
    color: #f4f4f5;
    font: 400 17px "DM Mono", monospace;
    outline: none;
  }
  .gen {
    width: 44px;
    height: 44px;
    flex: none;
    border-radius: 22px;
    border: 0;
    background: #1c1c1f;
    color: #ffb27f;
    display: grid;
    place-items: center;
  }
  .gen.plain {
    background: none;
    color: #d4d4d8;
  }
  .meter {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 4px;
  }
  .bars {
    flex: 1;
    height: 6px;
    border-radius: 3px;
    background: #2a2a2e;
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 3px;
  }
  .bars span {
    border-radius: 3px;
  }
  .bars span.on {
    background: #fbbf24;
  }
  .good .bars span.on {
    background: #86efac;
  }
  .weak .bars span.on {
    background: #a1a1aa;
  }
  .what {
    font-size: 13px;
    color: #fbbf24;
  }
  .good .what {
    color: #86efac;
  }
  .weak .what {
    color: #a1a1aa;
  }
  .adds {
    display: flex;
    flex-direction: column;
    border-radius: 16px;
    border: 1px solid #1f1f22;
    background: #151517;
    overflow: hidden;
  }
  .add {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 56px;
    padding: 0 16px;
    border: 0;
    border-bottom: 1px solid #1f1f22;
    background: none;
    color: #f4f4f5;
    font: 400 16px "DM Sans Variable", sans-serif;
    text-align: left;
  }
  .add:last-child {
    border-bottom: 0;
  }
  .atext {
    flex: 1 0 auto;
    max-width: 75%;
    padding: 8px 0;
  }
  .ahint {
    flex: 0 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 14px;
    color: #a1a1aa;
  }
  .xhead {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 32px;
  }
  .xhead .lbl {
    flex: 1;
  }
  .xlabel {
    flex: 1;
    min-width: 0;
    padding: 4px 4px;
    border: 0;
    border-bottom: 1px solid #2a2a2e;
    background: none;
    color: #d4d4d8;
    font: 400 14px "DM Sans Variable", sans-serif;
    outline: none;
  }
  .xlabel:focus {
    border-bottom-color: #ff6a1a;
  }
  .xhide {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: none;
    font-size: 13px;
    color: #a1a1aa;
  }
  .xremove {
    width: 32px;
    height: 32px;
    flex: none;
    padding: 0;
    border: 0;
    border-radius: 16px;
    background: none;
    color: #a1a1aa;
    display: grid;
    place-items: center;
  }
  .plainfont {
    font-family: "DM Sans Variable", sans-serif !important;
    letter-spacing: 0 !important;
  }
  .err {
    margin: 0 4px;
    font-size: 14px;
    color: #fca5a5;
  }
  .foot {
    padding: 12px 16px calc(28px + var(--bb));
    border-top: 1px solid #1f1f22;
    display: flex;
    align-items: center;
    gap: 10px;
    color: #a1a1aa;
    font-size: 14px;
  }
  .to {
    color: #f4f4f5;
    font-weight: 500;
  }
  .fto {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .change {
    flex: none;
    margin-left: auto;
    min-height: 36px;
    padding: 0 14px;
    border-radius: 18px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #d4d4d8;
    font: 500 14px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .sh-title {
    margin: 0 8px 8px;
    font-size: 20px;
    font-weight: 500;
  }
  .vrow {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 64px;
    padding: 0 10px;
    border: 0;
    border-radius: 16px;
    background: transparent;
    color: #f4f4f5;
    text-align: left;
  }
  .vrow.current {
    background: rgba(255, 106, 26, 0.08);
  }
  .vbadge {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    background: #1c1c1f;
    display: grid;
    place-items: center;
    color: #ffb27f;
    font-weight: 600;
  }
  .vname {
    flex: 1;
    font-size: 16px;
    font-weight: 500;
  }
</style>
