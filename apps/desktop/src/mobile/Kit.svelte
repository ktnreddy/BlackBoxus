<script lang="ts">
  import KeyGrid from "./KeyGrid.svelte";
  import StepHeader from "./StepHeader.svelte";
  import type { EmergencyKit } from "../lib/api";

  /** The Emergency Kit to write down. Phones can't print from the app and
   *  block screenshots of it, so paper is the way to keep it. */
  let {
    kit,
    again = false,
    step = null,
    ondone,
  }: {
    kit: EmergencyKit;
    /** Shown again from settings: no need to confirm it was saved. */
    again?: boolean;
    /** Where this is in sign-up (3 of 4), if it is. */
    step?: string | null;
    ondone: () => void;
  } = $props();

  let written = $state(false);
</script>

<div class="m-fl">
  {#if step}
    <StepHeader step={3} />
  {:else}
    <header class="m-fl-top kt-bar">
      {#if again}<button type="button" class="kt-done" onclick={ondone}>Done</button>{/if}
    </header>
  {/if}
  <main class="m-fl-main kt-main">
    {#if step}<p class="m-fl-step">Step 3 of 4</p>{/if}
    <h1 class="m-fl-title kt-title">
      {again ? "Your Emergency Kit" : kit.recovery_key && !step ? "Write down your new recovery key" : "Write down your Secret Key"}
    </h1>
    <p class="m-fl-lede">
      You need it with your master password on any new device. Screenshots are blocked to keep it off
      your photo backups.
    </p>
    <div class="kt-box">
      <span class="kt-label">Secret Key · for {kit.email}</span>
      <KeyGrid text={kit.secret_key} />
      <span class="kt-label">
        This is one key, {kit.secret_key.replaceAll("-", "").length} characters long. The dashes only split it
        into groups so it's easier to copy; you can type it with or without them. It has no letters O or I,
        so nothing is mistaken for 0 or 1.
      </span>
    </div>
    {#if kit.recovery_key}
      <div class="kt-box">
        <span class="kt-label">Recovery key · shown only now</span>
        <KeyGrid text={kit.recovery_key} numbered />
        <span class="kt-label">
          A second, separate key: {kit.recovery_key.split("-").filter((w) => w !== "").length} words, kept in this
          order. It lets you choose a new master password if you ever forget yours. This is the only time it is
          shown.
        </span>
      </div>
    {/if}
    {#if !again}
      <label class="kt-confirm">
        <input class="m-check" type="checkbox" bind:checked={written} />
        I've written it down and kept it somewhere safe
      </label>
    {/if}
  </main>
  {#if !again}
    <footer class="m-fl-foot">
      <button type="button" class="m-fl-btn" disabled={!written} onclick={ondone}>Continue</button>
    </footer>
  {/if}
</div>

<style>
  .kt-bar {
    display: flex;
    justify-content: flex-end;
    min-height: 44px;
  }
  .kt-done {
    min-height: 44px;
    padding: 0 18px;
    border-radius: 22px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #f4f4f5;
    font: 500 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .kt-main {
    padding-top: 16px;
    padding-bottom: 16px;
  }
  .kt-title {
    font-size: 32px;
  }
  .kt-box {
    margin-top: 6px;
    padding: 22px 18px;
    border-radius: 22px;
    background: #151517;
    border: 1px solid rgba(255, 106, 26, 0.38);
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .kt-label {
    font-size: 13px;
    color: #a1a1aa;
  }
  .kt-confirm {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 56px;
    padding: 0 16px;
    border-radius: 18px;
    background: #151517;
    border: 1px solid #1f1f22;
    font-size: 16px;
  }
</style>
