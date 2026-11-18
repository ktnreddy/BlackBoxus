<script lang="ts">
  import { untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import {
    copyText,
    errorMessage,
    generatePassword,
    type Generated,
    type GeneratorOptions,
  } from "../lib/api";

  let { onnotice }: { onnotice: (text: string) => void } = $props();

  let kind = $state<"passphrase" | "random">("passphrase");
  let length = $state(20);
  let digits = $state(true);
  let symbols = $state(true);
  let words = $state(4);
  let separator = $state("-");
  let number = $state(true);
  let result = $state<Generated | null>(null);
  let error = $state("");

  const options = $derived<GeneratorOptions>(
    kind === "random"
      ? { kind, length, digits, symbols }
      : { kind, words, separator, capitalise: false, number },
  );

  async function regenerate() {
    try {
      result = await generatePassword(options);
      error = "";
    } catch (e) {
      error = errorMessage(e);
    }
  }

  $effect(() => {
    void options;
    untrack(regenerate);
  });

  // Don't keep a password on screen after leaving the tab.
  $effect(() => () => (result = null));

  async function copy() {
    if (!result) return;
    try {
      await copyText(result.password);
      onnotice("Copied · clears in 30 s");
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  /** The passphrase split so every other word can be tinted. */
  const parts = $derived.by(() => {
    if (!result) return [];
    if (kind !== "passphrase" || !separator) return [{ text: result.password, alt: false }];
    const out: { text: string; alt: boolean }[] = [];
    result.password.split(separator).forEach((w, i, all) => {
      out.push({ text: w, alt: i % 2 === 1 && !/^\d+$/.test(w) });
      if (i < all.length - 1) out.push({ text: separator, alt: false });
    });
    return out;
  });
  const SCORES: Record<string, number> = { "Very strong": 4, Strong: 3, Fair: 2 };
  const score = $derived(result ? (SCORES[result.label] ?? 1) : 0);
  const tone = $derived(score >= 4 ? "good" : score === 3 ? "ok" : "bad");
  const SEPARATORS = [
    { value: "-", label: "Hyphen", text: "-" },
    { value: ".", label: "Full stop", text: "." },
    { value: " ", label: "Space", text: "space" },
  ];
</script>

<header class="gn-head"><h1 class="gn-h1">Generator</h1></header>

<div class="gn-main m-scroll">
  <div class="gn-seg" role="group" aria-label="Kind">
    <button type="button" aria-pressed={kind === "passphrase"} onclick={() => (kind = "passphrase")}>Passphrase</button>
    <button type="button" aria-pressed={kind === "random"} onclick={() => (kind = "random")}>Random</button>
  </div>

  <div class="gn-result">
    <p class="gn-pw" aria-live="polite">
      {#each parts as p, i (i)}{#if p.alt}<span class="gn-alt">{p.text}</span>{:else}{p.text}{/if}{/each}
    </p>
    {#if result}
      <div class="gn-meter {tone}">
        <div class="gn-bars" aria-hidden="true">
          {#each [1, 2, 3, 4] as n (n)}<span class:on={score >= n}></span>{/each}
        </div>
        <span class="gn-what">{result.label} · {kind === "passphrase" ? `${words} words` : `${length} characters`}</span>
      </div>
    {/if}
    {#if error}<p class="m-error" role="alert">{error}</p>{/if}
  </div>

  <div class="gn-two">
    <button type="button" class="gn-new" onclick={regenerate}>
      <Icon name="refresh" size={20} />New one
    </button>
    <button type="button" class="gn-copy" onclick={copy} disabled={!result}>
      <Icon name="copy" size={20} />Copy
    </button>
  </div>

  <div class="gn-group">
    {#if kind === "passphrase"}
      <div class="gn-slider">
        <div class="gn-line"><label for="g-words">Words</label><span class="gn-val">{words}</span></div>
        <input class="gn-range" id="g-words" type="range" min="3" max="10" bind:value={words} />
      </div>
      <div class="gn-opt">
        <span>Separator</span>
        <div class="gn-seps" role="group" aria-label="Separator">
          {#each SEPARATORS as sep (sep.value)}
            <button type="button" class="gn-sep" class:word={sep.value === " "} aria-label={sep.label} aria-pressed={separator === sep.value} onclick={() => (separator = sep.value)}>
              {sep.text}
            </button>
          {/each}
        </div>
      </div>
      <label class="gn-opt end">
        <span>Add a number</span>
        <input class="m-switch" type="checkbox" role="switch" bind:checked={number} />
      </label>
    {:else}
      <div class="gn-slider">
        <div class="gn-line"><label for="g-len">Length</label><span class="gn-val">{length}</span></div>
        <input class="gn-range" id="g-len" type="range" min="8" max="64" bind:value={length} />
      </div>
      <label class="gn-opt">
        <span>Numbers</span>
        <input class="m-switch" type="checkbox" role="switch" bind:checked={digits} />
      </label>
      <label class="gn-opt end">
        <span>Symbols</span>
        <input class="m-switch" type="checkbox" role="switch" bind:checked={symbols} />
      </label>
    {/if}
  </div>
  <p class="gn-fine">
    {kind === "passphrase"
      ? "Words come from the EFF list. Nothing you make here is saved unless you put it in an item."
      : "Nothing you make here is saved unless you put it in an item."}
  </p>
</div>

<style>
  .gn-head {
    padding: calc(56px + var(--sb)) 24px 8px;
  }
  .gn-h1 {
    margin: 0;
    font-size: 30px;
    font-weight: 400;
    letter-spacing: -0.02em;
  }
  .gn-main {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 12px 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .gn-main > * {
    flex: none;
  }
  .gn-seg {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    padding: 4px;
    border-radius: 24px;
    background: #151517;
    border: 1px solid #1f1f22;
  }
  .gn-seg button {
    min-height: 44px;
    border: 0;
    border-radius: 20px;
    background: none;
    color: #a1a1aa;
    font: 500 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    overflow-wrap: anywhere;
  }
  .gn-seg button[aria-pressed="true"] {
    background: #2a2a2e;
    color: #f4f4f5;
  }
  .gn-result {
    padding: 28px 22px;
    border-radius: 24px;
    background: #151517;
    border: 1px solid rgba(255, 106, 26, 0.38);
    display: flex;
    flex-direction: column;
    gap: 18px;
  }
  .gn-pw {
    margin: 0;
    font-family: var(--font-mono);
    font-size: 24px;
    line-height: 1.45;
    word-break: break-word;
    min-height: 35px;
    user-select: text;
    -webkit-user-select: text;
  }
  .gn-alt {
    color: #ffb27f;
  }
  .gn-meter {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .gn-bars {
    width: 120px;
    height: 6px;
    border-radius: 3px;
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 3px;
  }
  .gn-bars span {
    background: #2a2a2e;
    border-radius: 3px;
  }
  .gn-what {
    font-size: 13px;
  }
  .good .gn-bars .on {
    background: #86efac;
  }
  .good .gn-what {
    color: #86efac;
  }
  .ok .gn-bars .on {
    background: #ffb27f;
  }
  .ok .gn-what {
    color: #ffb27f;
  }
  .bad .gn-bars .on {
    background: #fca5a5;
  }
  .bad .gn-what {
    color: #fca5a5;
  }
  .gn-two {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }
  .gn-new,
  .gn-copy {
    min-height: 56px;
    border-radius: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .gn-new {
    border: 1px solid #2a2a2e;
    background: none;
    color: #f4f4f5;
    font: 500 16px "DM Sans Variable", sans-serif;
  }
  .gn-copy {
    border: 0;
    background: #ff6a1a;
    color: #140800;
    font: 600 16px "DM Sans Variable", sans-serif;
  }
  .gn-copy:disabled {
    opacity: 0.5;
  }
  .gn-group {
    border-radius: 20px;
    background: #151517;
    border: 1px solid #1f1f22;
    overflow: hidden;
  }
  .gn-slider {
    padding: 16px 18px;
    border-bottom: 1px solid #1f1f22;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .gn-line {
    display: flex;
    justify-content: space-between;
    font-size: 16px;
  }
  .gn-val {
    color: #ffb27f;
    font-weight: 500;
  }
  .gn-range {
    width: 100%;
    margin: 2px;
    accent-color: #ff6a1a;
  }
  .gn-opt {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px 12px;
    min-height: 60px;
    padding: 8px 18px;
    box-sizing: border-box;
    border-bottom: 1px solid #1f1f22;
    font-size: 16px;
  }
  .gn-opt.end {
    border-bottom: 0;
  }
  .gn-seps {
    display: flex;
    gap: 6px;
  }
  .gn-sep {
    min-width: 44px;
    padding-left: 8px;
    padding-right: 8px;
    min-height: 36px;
    border-radius: 12px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #d4d4d8;
    font: 500 16px var(--font-mono);
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .gn-sep.word {
    font: 500 13px "DM Sans Variable", sans-serif;
  }
  .gn-sep[aria-pressed="true"] {
    border: 0;
    background: #ff6a1a;
    color: #140800;
  }
  .gn-fine {
    margin: 0 6px;
    font-size: 13px;
    color: #a1a1aa;
    line-height: 1.5;
  }
</style>
