<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import {
    copyText,
    errorMessage,
    generatePassword,
    type Generated,
    type GeneratorOptions,
  } from "../../api";

  let {
    onuse,
    onclose,
    onnotice,
  }: {
    /** Set when opened from the item editor: puts the password in the form. */
    onuse?: (password: string) => void;
    onclose: () => void;
    onnotice: (text: string) => void;
  } = $props();

  let kind = $state<"random" | "passphrase">("random");
  let length = $state(20);
  let digits = $state(true);
  let symbols = $state(true);
  let words = $state(5);
  let separator = $state("-");
  let capitalise = $state(true);
  let number = $state(true);
  let result = $state<Generated | null>(null);
  let error = $state("");

  const options = $derived<GeneratorOptions>(
    kind === "random"
      ? { kind, length, digits, symbols }
      : { kind, words, separator, capitalise, number },
  );

  async function regenerate() {
    try {
      result = await generatePassword(options);
      error = "";
    } catch (e) {
      error = errorMessage(e);
    }
  }

  // A new password whenever an option changes.
  $effect(() => {
    void options;
    regenerate();
  });

  const parts = $derived(
    result === null
      ? []
      : kind === "passphrase" && separator
        ? result.password.split(separator)
        : [result.password],
  );
  /** Ten segments, one per 10 bits, so no inline styles are needed. */
  const meter = $derived(result ? Math.min(10, Math.round(result.bits / 10)) : 0);

  function close() {
    result = null;
    onclose();
  }

  async function copy() {
    if (!result) return;
    try {
      await copyText(result.password);
      onnotice("Copied. The clipboard clears in 30 seconds.");
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Escape") close();
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop" role="presentation">
  <div class="card accent dialog" role="dialog" aria-modal="true" aria-labelledby="gen-title">
    <div class="top">
      <h1 id="gen-title" class="title">Generate a password</h1>
      <button type="button" class="icon-btn" aria-label="Close" onclick={close}>
        <Icon name="x" />
      </button>
    </div>

    <div class="seg" role="group" aria-label="Kind">
      <button type="button" aria-pressed={kind === "random"} onclick={() => (kind = "random")}
        >Random</button
      >
      <button
        type="button"
        aria-pressed={kind === "passphrase"}
        onclick={() => (kind = "passphrase")}>Passphrase</button
      >
    </div>

    <div class="output">
      <output class="mono selectable" aria-live="polite">
        {#each parts as part, i (i)}{#if i > 0}<span class="sep">{separator}</span>{/if}{part}{/each}
      </output>
      <div class="out-actions">
        <button type="button" class="icon-btn" aria-label="New password" onclick={regenerate}>
          <Icon name="refresh" />
        </button>
        <button type="button" class="icon-btn" aria-label="Copy" onclick={copy}>
          <Icon name="copy" />
        </button>
      </div>
    </div>

    {#if result}
      <div class="strength">
        <div class="bar" aria-hidden="true">
          {#each Array.from({ length: 10 }, (_, n) => n) as n (n)}<span class:on={n < meter}></span>{/each}
        </div>
        <span class="small"><span class="hi-label">{result.label}</span> · about {result.bits} bits</span>
      </div>
    {/if}

    {#if kind === "random"}
      <div>
        <div class="slider-head">
          <label for="gen-length">Length</label><span class="big">{length}</span>
        </div>
        <input id="gen-length" type="range" min="8" max="64" bind:value={length} />
      </div>
      <div class="toggles">
        <label class="toggle"
          ><span>Numbers</span><input type="checkbox" role="switch" bind:checked={digits} /></label
        >
        <label class="toggle"
          ><span>Symbols</span><input type="checkbox" role="switch" bind:checked={symbols} /></label
        >
      </div>
    {:else}
      <div>
        <div class="slider-head">
          <label for="gen-words">Words</label><span class="big">{words}</span>
        </div>
        <input id="gen-words" type="range" min="3" max="10" bind:value={words} />
      </div>
      <div class="toggles">
        <label class="toggle"
          ><span>Capitalise a word</span><input
            type="checkbox"
            role="switch"
            bind:checked={capitalise}
          /></label
        >
        <label class="toggle"
          ><span>Add a number</span><input type="checkbox" role="switch" bind:checked={number} /></label
        >
        <div class="toggle">
          <span id="sep-label">Separator</span>
          <div class="seg" role="group" aria-labelledby="sep-label">
            {#each [["-", "Hyphen"], [" ", "Space"], [".", "Period"]] as [value, text] (value)}
              <button
                type="button"
                aria-pressed={separator === value}
                onclick={() => (separator = value ?? "-")}>{text}</button
              >
            {/each}
          </div>
        </div>
      </div>
    {/if}

    {#if error}
      <p class="note" role="alert"><Icon name="alert" />{error}</p>
    {/if}

    <div class="row actions">
      {#if onuse}
        <button type="button" class="btn ghost" onclick={close}>Cancel</button>
        <button
          type="button"
          class="btn primary"
          disabled={!result}
          onclick={() => {
            if (result) onuse?.(result.password);
            close();
          }}>Use this password</button
        >
      {:else}
        <button type="button" class="btn ghost" onclick={close}>Close</button>
        <button type="button" class="btn primary" disabled={!result} onclick={copy}>
          <Icon name="copy" size={16} />Copy
        </button>
      {/if}
    </div>
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
    width: min(640px, calc(100vw - 48px));
    padding: 32px 36px;
    display: flex;
    flex-direction: column;
    gap: 20px;
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
  .seg {
    align-self: flex-start;
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
  .output {
    background: #0e0e10;
    border: 1px solid var(--line);
    border-radius: 20px;
    padding: 20px 22px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  output {
    font-size: 20px;
    overflow-wrap: anywhere;
    min-width: 0;
  }
  .sep {
    color: var(--accent);
  }
  .out-actions {
    display: flex;
    gap: 4px;
    flex: none;
  }
  .strength {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .bar {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(10, 1fr);
    gap: 3px;
  }
  .bar span {
    height: 4px;
    border-radius: 2px;
    background: var(--line);
  }
  .bar span.on {
    background: var(--accent);
  }
  .hi-label {
    color: var(--accent);
    font-weight: 500;
  }
  .slider-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 10px;
    font-size: 15px;
  }
  .big {
    font-size: 28px;
    font-weight: 300;
    color: var(--accent);
    line-height: 1;
  }
  input[type="range"] {
    width: 100%;
    margin: 0;
    accent-color: var(--accent);
  }
  .toggles {
    display: flex;
    flex-direction: column;
  }
  .toggle {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 0;
    border-top: 1px solid var(--hair);
    font-size: 15px;
    cursor: pointer;
  }
  .toggle input[type="checkbox"] {
    appearance: none;
    width: 40px;
    height: 24px;
    border-radius: 999px;
    background: var(--line);
    position: relative;
    margin: 0;
    cursor: pointer;
    flex: none;
  }
  .toggle input[type="checkbox"]::after {
    content: "";
    position: absolute;
    top: 3px;
    left: 3px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--muted);
    transition: left 0.12s;
  }
  .toggle input[type="checkbox"]:checked {
    background: var(--accent);
  }
  .toggle input[type="checkbox"]:checked::after {
    left: 19px;
    background: var(--accent-ink);
  }
  .actions {
    justify-content: flex-end;
  }
</style>
