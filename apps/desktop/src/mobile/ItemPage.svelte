<script lang="ts">
  import Icon from "./Icon.svelte";
  import { back } from "./nav";
  import { tint } from "./tint";
  import {
    copyField,
    copyText,
    errorMessage,
    getItem,
    openWebsite,
    revealField,
    totpCode,
    type ItemView,
    type TotpCode,
  } from "../lib/api";

  let {
    vault,
    vaultName,
    itemId,
    subtitle = "",
    writable,
    onedit,
    onmore,
    onnotice,
  }: {
    vault: string;
    vaultName: string;
    itemId: string;
    /** The list line, for a card's last four digits. */
    subtitle?: string;
    writable: boolean;
    onedit: (item: ItemView) => void;
    onmore: () => void;
    onnotice: (text: string) => void;
  } = $props();

  const LABELS: Record<string, string> = {
    username: "Username",
    password: "Password",
    url: "Website",
    notes: "Notes",
    totp: "One-time code",
    cardholder: "Name on card",
    card_number: "Card number",
    card_expiry: "Expires",
    card_code: "Security code",
    text: "Text",
    concealed: "Hidden text",
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
  let revealed = $state<Record<number, string>>({});

  $effect(() => {
    getItem(vault, itemId).then(
      (i) => (item = i),
      (e: unknown) => (error = errorMessage(e)),
    );
  });

  function label(f: { kind: string; label: string }): string {
    return f.label || LABELS[f.kind] || "Field";
  }

  const timers = new Map<number, ReturnType<typeof setTimeout>>();
  $effect(() => () => timers.forEach((t) => clearTimeout(t)));

  function hide(index: number) {
    const { [index]: _, ...rest } = revealed;
    revealed = rest;
  }

  async function show(index: number) {
    try {
      revealed = { ...revealed, [index]: await revealField(vault, itemId, index) };
      clearTimeout(timers.get(index));
      timers.set(
        index,
        setTimeout(() => hide(index), 30_000),
      );
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  function toggle(index: number) {
    if (index in revealed) hide(index);
    else show(index);
  }

  async function copy(index: number, kind: string, concealed: boolean) {
    try {
      await copyField(vault, itemId, index);
      const what = LABELS[kind] ?? "It";
      onnotice(concealed ? `${what} copied · clears in 30 s` : `${what} copied`);
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  async function open() {
    try {
      await openWebsite(vault, itemId);
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  // The one-time code, computed in Rust every second.
  let code = $state<TotpCode | null>(null);
  const totpIndex = $derived(item ? item.fields.findIndex((f) => f.kind === "totp") : -1);
  $effect(() => {
    const index = totpIndex;
    if (index < 0) return;
    let stopped = false;
    const tick = () =>
      totpCode(vault, itemId, index).then(
        (c) => {
          if (!stopped) code = c;
        },
        () => {},
      );
    tick();
    const timer = setInterval(tick, 1000);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  });
  const RING = 2 * Math.PI * 24;
  const shownCode = $derived(code ? `${code.code.slice(0, 3)} ${code.code.slice(3)}` : "");

  async function copyCode() {
    if (!code) return;
    try {
      await copyText(code.code);
      onnotice("Code copied · clears in 30 s");
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  const indexed = $derived(item ? item.fields.map((f, i) => ({ f, i })) : []);
  const account = $derived(indexed.filter(({ f }) => f.kind === "username" || f.kind === "password"));
  const website = $derived(indexed.find(({ f }) => f.kind === "url" && f.value) ?? null);
  const notes = $derived(indexed.filter(({ f }) => f.kind === "notes" && f.value));
  const others = $derived(
    indexed.filter(({ f }) => !["username", "password", "url", "notes", "totp"].includes(f.kind)),
  );
  const last4 = $derived(/•••• (\d{4})/.exec(subtitle)?.[1] ?? "••••");
  const holder = $derived(item?.fields.find((f) => f.kind === "cardholder")?.value ?? "");
  const expiry = $derived(item?.fields.find((f) => f.kind === "card_expiry")?.value ?? "");

  function edited(ms: number): string {
    const days = Math.floor((Date.now() - ms) / 86_400_000);
    if (days < 1) return "Edited today";
    if (days === 1) return "Edited yesterday";
    if (days < 30) return `Edited ${days} days ago`;
    return `Edited ${new Date(ms).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })}`;
  }
  const host = (url: string) => url.replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "");
  const MONO = new Set(["card_number", "card_expiry", "card_code"]);
</script>

<div class="screen">
  <header class="head">
    <button type="button" class="back" aria-label="Back" onclick={back}><Icon name="back" size={22} /></button>
    {#if item?.type === "card"}
      {#if writable}<button type="button" class="edit" onclick={() => item && onedit(item)}>Edit</button>{/if}
    {:else}
      <div class="right">
        {#if writable && item}<button type="button" class="edit" onclick={() => item && onedit(item)}>Edit</button>{/if}
        <button type="button" class="more" aria-label="More actions" onclick={onmore}><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M11 12a1 1 0 1 0 2 0a1 1 0 1 0 -2 0M11 5a1 1 0 1 0 2 0a1 1 0 1 0 -2 0M11 19a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" /></svg></button>
      </div>
    {/if}
  </header>

  {#if error}
    <p class="err" role="alert">{error}</p>
  {:else if item?.type === "card"}
    <main class="cmain">
      <div class="ccard">
        <div class="cline"><span class="cname">{item.title}</span><span class="lbl">{vaultName}</span></div>
        <span class="chip" aria-hidden="true"></span>
        <span class="cnum">•••• •••• •••• {last4}</span>
        <div class="cfoot"><span>{holder.toUpperCase()}</span><span>{expiry.replace(/\s/g, "")}</span></div>
      </div>
      <div class="box">
        {#each indexed.filter(({ f }) => f.kind !== "notes") as { f, i } (i)}
          <div class="crow">
            <div class="ctext">
              <span class="lbl">{label(f)}</span>
              <span class="cval" class:mono={MONO.has(f.kind)}>
                {#if f.concealed}{i in revealed ? revealed[i] : f.kind === "card_number" ? `•••• •••• •••• ${last4}` : "•••"}{:else}{f.value}{/if}
              </span>
            </div>
            {#if f.concealed}
              <button
                type="button"
                class="ceye"
                aria-label={`Hold to show ${label(f)}`}
                onpointerdown={() => show(i)}
                onpointerup={() => hide(i)}
                onpointerleave={() => hide(i)}
                oncontextmenu={(e) => e.preventDefault()}
              >
                <Icon name="eye" size={20} />
              </button>
            {/if}
            <button type="button" class="ccopy" aria-label={`Copy ${label(f)}`} onclick={() => copy(i, f.kind, f.concealed)}>
              <Icon name="copy" size={18} />
            </button>
          </div>
        {/each}
      </div>
      <p class="foot">The full number and security code only show while you hold the eye button.</p>
    </main>
  {:else if item}
    <section class="hero">
      <span class="badge">{item.title[0]?.toUpperCase() ?? "?"}</span>
      <div class="htext">
        <h1>{item.title}</h1>
        <span class="meta">{TYPES[item.type] ?? "Item"} · {vaultName}</span>
      </div>
    </section>
    <main class="imain">
      {#if account.length > 0}
        <div class="box">
          {#each account as { f, i } (i)}
            <div class="frow" class:pw={f.kind === "password"}>
              <div class="ftext">
                <span class="lbl">{label(f)}</span>
                {#if f.concealed}
                  {#if i in revealed}<span class="val mono selectable">{revealed[i]}</span>{:else}<span class="dots" aria-label="Hidden">••••••••••••</span>{/if}
                {:else}
                  <span class="val selectable">{f.value}</span>
                {/if}
              </div>
              {#if f.concealed}
                <button type="button" class="eye" aria-label={i in revealed ? `Hide ${label(f)}` : `Show ${label(f)}`} aria-pressed={i in revealed} onclick={() => toggle(i)}>
                  <Icon name={i in revealed ? "eyeOff" : "eye"} size={20} />
                </button>
              {/if}
              <button type="button" class="cp" class:accent={f.kind === "password"} aria-label={`Copy ${label(f)}`} onclick={() => copy(i, f.kind, f.concealed)}>
                <Icon name="copy" size={20} />
              </button>
            </div>
          {/each}
        </div>
      {/if}

      {#if totpIndex >= 0}
        <div class="card code">
          <svg width="56" height="56" viewBox="0 0 56 56" role="img" aria-label={`${code?.remaining ?? 0} seconds left`}>
            <circle cx="28" cy="28" r="24" fill="none" stroke="#2a2a2e" stroke-width="5" />
            <circle cx="28" cy="28" r="24" fill="none" stroke="#ff6a1a" stroke-width="5" stroke-linecap="round" stroke-dasharray="150.8" stroke-dashoffset={code ? 150.8 * (1 - code.remaining / code.period) : 0} transform="rotate(-90 28 28)" />
            <text x="28" y="33" text-anchor="middle" font-size="15" font-weight="600" fill="#f4f4f5">{code?.remaining ?? ""}</text>
          </svg>
          <div class="otext">
            <span class="lbl">One-time code</span>
            <span class="otp selectable">{shownCode}</span>
          </div>
          <button type="button" class="cp" aria-label="Copy one-time code" onclick={copyCode} disabled={!code}><Icon name="copy" size={20} /></button>
        </div>
      {/if}

      {#if website && website.f.value}
        <button type="button" class="card site" onclick={open}>
          <span class="stext">
            <span class="lbl">Website</span>
            <span class="host">{host(website.f.value)}</span>
          </span>
          <Icon name="open" size={20} />
        </button>
      {/if}

      {#each notes as { f, i } (i)}
        <div class="card notes">
          <span class="lbl">{label(f)}</span>
          <span class="ntext selectable">{f.value}</span>
        </div>
      {/each}

      {#if others.length > 0}
        <div class="box">
          {#each others as { f, i } (i)}
            <div class="frow">
              <div class="ftext">
                <span class="lbl">{label(f)}</span>
                {#if f.concealed}
                  {#if i in revealed}<span class="val mono selectable">{revealed[i]}</span>{:else}<span class="dots" aria-label="Hidden">••••••••••••</span>{/if}
                {:else}
                  <span class="val selectable">{f.value}</span>
                {/if}
              </div>
              {#if f.concealed}
                <button type="button" class="eye" aria-label={i in revealed ? `Hide ${label(f)}` : `Show ${label(f)}`} onclick={() => toggle(i)}><Icon name="eye" size={20} /></button>
              {/if}
              <button type="button" class="cp" aria-label={`Copy ${label(f)}`} onclick={() => copy(i, f.kind, f.concealed)}><Icon name="copy" size={20} /></button>
            </div>
          {/each}
        </div>
      {/if}

      <p class="edited">{edited(item.modified_ms)} · Copied passwords clear after 30 seconds</p>
    </main>
  {/if}
</div>

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
  .back {
    width: 44px;
    height: 44px;
    border: 0;
    border-radius: 22px;
    background: none;
    display: grid;
    place-items: center;
    color: #f4f4f5;
  }
  .right {
    display: flex;
    gap: 4px;
  }
  .edit {
    min-height: 46px;
    padding: 0 18px;
    border-radius: 22px;
    border: 1px solid #2a2a2e;
    background: none;
    display: flex;
    align-items: center;
    color: #f4f4f5;
    font-size: 15px;
    font-weight: 500;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .more {
    width: 44px;
    height: 44px;
    border-radius: 22px;
    border: 0;
    background: none;
    color: #d4d4d8;
    display: grid;
    place-items: center;
  }
  .err {
    margin: 16px;
    color: #fca5a5;
  }
  .hero {
    padding: 8px 24px 20px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .badge {
    width: 60px;
    height: 60px;
    flex: none;
    border-radius: 16px;
    background: #1c1c1f;
    display: grid;
    place-items: center;
    font-size: 24px;
    font-weight: 600;
    color: #f4f4f5;
  }
  .htext {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  h1 {
    margin: 0;
    font-size: 26px;
    font-weight: 500;
    letter-spacing: -0.02em;
    overflow-wrap: anywhere;
  }
  .meta {
    font-size: 14px;
    color: #a1a1aa;
  }
  .imain {
    flex: 1;
    padding: 0 16px calc(24px + var(--bb));
    display: flex;
    flex-direction: column;
    gap: 12px;
    overflow-y: auto;
  }
  .imain > *,
  .cmain > * {
    flex-shrink: 0;
  }
  .box {
    background: #151517;
    border: 1px solid #1f1f22;
    border-radius: 20px;
    overflow: hidden;
  }
  .frow {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 8px 14px 18px;
    border-bottom: 1px solid #1f1f22;
  }
  .frow.pw {
    gap: 8px;
  }
  .frow:last-child {
    border-bottom: 0;
  }
  .ftext {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .lbl {
    font-size: 13px;
    color: #a1a1aa;
  }
  .val {
    font-size: 17px;
    overflow-wrap: anywhere;
  }
  .mono {
    font-family: "DM Mono", monospace;
  }
  .dots {
    font-size: 20px;
    letter-spacing: 3px;
    color: #d4d4d8;
  }
  .cp,
  .eye {
    width: 48px;
    height: 48px;
    flex: none;
    border-radius: 24px;
    border: 0;
    background: #1c1c1f;
    color: #f4f4f5;
    display: grid;
    place-items: center;
  }
  .eye {
    background: none;
    color: #d4d4d8;
  }
  .cp.accent {
    background: #ff6a1a;
    color: #140800;
  }
  .cp:disabled {
    opacity: 0.5;
  }
  .card {
    background: #151517;
    border: 1px solid #1f1f22;
    border-radius: 20px;
    padding: 16px 18px;
  }
  .code {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .code text {
    font-family: "DM Sans Variable", sans-serif;
  }
  .otext {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .otp {
    font-family: "DM Mono", monospace;
    /* 30px on a normal phone, smaller on narrow ones so it stays on one line. */
    font-size: clamp(20px, calc(30px - (390px - 100vw) * 0.12), 30px);
    letter-spacing: 2px;
    white-space: nowrap;
  }
  .site {
    box-sizing: content-box;
    display: flex;
    align-items: center;
    gap: 12px;
    color: #f4f4f5;
    text-align: left;
    font: inherit;
  }
  .stext {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .host {
    font-size: 16px;
    overflow-wrap: anywhere;
  }
  .site :global(svg) {
    color: #a1a1aa;
  }
  .notes {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .ntext {
    font-size: 15px;
    line-height: 1.5;
    color: #d4d4d8;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .edited {
    margin: 4px 6px;
    font-size: 13px;
    color: #a1a1aa;
  }
  .cmain {
    flex: 1;
    padding: 8px 16px calc(24px + var(--bb));
    display: flex;
    flex-direction: column;
    gap: 14px;
    overflow-y: auto;
  }
  .ccard {
    height: 214px;
    box-sizing: border-box;
    padding: 22px;
    border-radius: 22px;
    background: linear-gradient(135deg, #1f1f23, #121214);
    border: 1px solid #2a2a2e;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .cline {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
  }
  .cname {
    font-size: 17px;
    font-weight: 500;
    flex: none;
    max-width: 60%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cline .lbl {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .chip {
    width: 44px;
    height: 32px;
    border-radius: 6px;
    background: #3f3f46;
  }
  .cnum {
    font-family: "DM Mono", monospace;
    /* 22px on a normal phone; smaller on narrow ones so the number stays on one line. */
    font-size: clamp(16px, calc(22px - (390px - 100vw) * 0.1), 22px);
    letter-spacing: 2px;
    white-space: nowrap;
  }
  .cfoot {
    display: flex;
    justify-content: space-between;
    font-size: 14px;
    color: #d4d4d8;
  }
  .crow {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 8px 12px 18px;
    border-bottom: 1px solid #1f1f22;
  }
  .ctext {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .cval {
    font-size: 17px;
  }
  .ceye,
  .ccopy {
    width: 44px;
    height: 44px;
    flex: none;
    border-radius: 22px;
    border: 0;
    background: none;
    color: #d4d4d8;
    display: grid;
    place-items: center;
  }
  .ccopy {
    background: #1c1c1f;
    color: #f4f4f5;
  }
  .foot {
    margin: 0 6px;
    font-size: 13px;
    color: #a1a1aa;
  }
</style>
