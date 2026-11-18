<script lang="ts">
  import Icon from "./Icon.svelte";
  import StepHeader from "./StepHeader.svelte";
  import { errorMessage, helloEnable, isAppError, type AppStatus } from "../lib/api";
  import { unlockWords } from "../lib/unlockWords";

  /** Offered once after sign-up or sign-in: unlock with a fingerprint. */
  let {
    status,
    signup = true,
    changed = false,
    ondone,
  }: {
    status: AppStatus;
    signup?: boolean;
    /** Offered again because the phone's fingerprints changed. */
    changed?: boolean;
    ondone: (status: AppStatus | null) => void;
  } = $props();

  const w = $derived(unlockWords(status));
  let busy = $state(false);
  let error = $state("");

  async function turnOn() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      ondone(await helloEnable());
    } catch (e) {
      // Closing the fingerprint prompt just leaves the choice here.
      error = isAppError(e) && e.code === "hello_cancelled" ? "" : errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="m-fl">
  {#if signup}<StepHeader step={4} />{:else}<div class="m-fl-top"><span class="fo-bar"></span></div>{/if}
  <main class="m-fl-main fo-main">
    {#if signup}<p class="m-fl-step">Step 4 of 4</p>{/if}
    <h1 class="m-fl-title">{changed ? `Set up ${w.unlock} again?` : `Unlock with ${w.name === "fingerprint" ? "your fingerprint" : w.name}?`}</h1>
    <p class="m-fl-lede">
      {changed
        ? `${w.name === "Face ID" ? "Face ID" : `The ${w.things}`} on this ${w.device} changed, so ${w.unlock} was turned off to keep your vault safe. Turn it back on with a quick check.`
        : `Faster than typing your master password every time. The key stays in this ${w.device}'s secure chip and never leaves it.`}
    </p>
    <span class="fo-print" aria-hidden="true"><Icon name={w.icon === "face" ? "face" : "fingerprint"} size={64} weight={1.4} /></span>
    <p class="fo-note">You'll still type your master password once every 14 days, so you don't forget it.</p>
    {#if error}<p class="m-error fo-center" role="alert">{error}</p>{/if}
  </main>
  <footer class="m-fl-foot fo-foot">
    <button type="button" class="m-fl-btn" onclick={turnOn} disabled={busy}>
      {busy ? w.waiting : `Turn on ${w.unlock}`}
    </button>
    <button type="button" class="fo-later" onclick={() => ondone(null)} disabled={busy}>Not now</button>
  </footer>
</div>

<style>
  .fo-bar {
    display: block;
    height: 44px;
  }
  .fo-main {
    padding-top: 24px;
  }
  .fo-print {
    margin: clamp(16px, calc(100vh - 800px), 44px) auto 0;
    width: 132px;
    height: 132px;
    border-radius: 66px;
    border: 1px solid rgba(255, 106, 26, 0.38);
    background: rgba(255, 106, 26, 0.1);
    display: grid;
    place-items: center;
    color: #ff6a1a;
  }
  .fo-note {
    margin: 28px 4px 0;
    font-size: 14px;
    color: #a1a1aa;
    line-height: 1.5;
    text-align: center;
  }
  .fo-center {
    text-align: center;
  }
  .fo-foot {
    gap: 10px;
  }
  .fo-later {
    min-height: 48px;
    border-radius: 24px;
    border: 0;
    background: none;
    color: #d4d4d8;
    font: 500 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
</style>
