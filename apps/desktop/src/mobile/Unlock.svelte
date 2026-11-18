<script lang="ts">
  import { untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import PasswordInput from "./PasswordInput.svelte";
  import {
    appStatus,
    errorMessage,
    isAppError,
    signOut,
    unlock,
    unlockWithHello,
    type AppStatus,
  } from "../lib/api";
  import { unlockWords } from "../lib/unlockWords";

  let {
    status,
    notice = "",
    onchange,
    onforgot,
    onfingerprintreset,
  }: {
    status: AppStatus;
    notice?: string;
    onchange: (s: AppStatus) => void;
    onforgot: () => void;
    /** Fingerprint unlock was turned off because the phone's fingerprints
     *  changed; offer to set it up again after the password unlock. */
    onfingerprintreset?: () => void;
  } = $props();

  const w = $derived(unlockWords(status));
  const fingerprintReady = $derived(
    status.hello.available && status.hello.enabled && !status.hello.needs_password,
  );

  let password = $state("");
  let busy = $state(false);
  let error = $state("");
  let typing = $state(false);
  let confirmSignOut = $state(false);

  async function withFingerprint() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      onchange(await unlockWithHello());
    } catch (e) {
      if (isAppError(e) && e.code === "hello_cancelled") {
        // Closing the prompt isn't an error: the sensor button stays.
        error = "";
      } else {
        error = errorMessage(e);
        if (isAppError(e) && (e.code === "hello_missing" || e.code === "hello_locked_out" || e.code === "password_needed")) {
          typing = true;
        }
        if (isAppError(e) && e.code === "hello_missing") {
          onfingerprintreset?.();
          // Unlocking with the fingerprint was turned off: show that.
          appStatus().then((s) => onchange(s), () => {});
        }
      }
    } finally {
      busy = false;
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || password.length === 0) return;
    busy = true;
    error = "";
    const typed = password;
    password = "";
    try {
      onchange(await unlock(typed));
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function notYou() {
    if (!confirmSignOut) {
      confirmSignOut = true;
      return;
    }
    busy = true;
    try {
      onchange(await signOut());
    } catch (e) {
      error = errorMessage(e);
      busy = false;
    }
  }

  // Ask for the fingerprint straight away when it's set up.
  let asked = false;
  $effect(() => {
    if (fingerprintReady && !asked && !notice) {
      asked = true;
      untrack(withFingerprint);
    }
  });

  const usePrint = $derived(fingerprintReady && !typing);
</script>

<div class="m-fl ul">
  <main class="ul-main">
    <img class="ul-logo" src="/logo.png" alt="BlackBoxus" width="84" height="84" />
    <h1 class="ul-title">Welcome back</h1>
    <p class="ul-who">{status.account?.email}</p>
    {#if usePrint}
      <button type="button" class="ul-print" onclick={withFingerprint} disabled={busy} aria-label={`Unlock with ${w.name}`}>
        <Icon name={w.icon === "face" ? "face" : "fingerprint"} size={52} weight={1.5} />
      </button>
      <p class="ul-hint">{w.icon === "face" ? `Tap to unlock with ${w.name}` : "Touch the sensor to unlock"}</p>
      {#if error || notice}<p class="m-error" role="alert">{error || notice}</p>{/if}
    {:else}
      <form id="unlock-form" class="ul-form" onsubmit={submit}>
        <PasswordInput id="master-password" label="Master password" size="plain" bind:value={password} disabled={busy} />
        {#if error || notice}
          <p class="m-error" role="alert">{error || notice}</p>
        {:else if status.hello.enabled && status.hello.needs_password}
          <p class="ul-note">It's been 14 days, so type your master password this time. {w.name === "fingerprint" ? "Your fingerprint" : w.name} works again after that.</p>
        {/if}
        <button type="submit" class="m-fl-btn" disabled={busy || password.length === 0}>{busy ? "Unlocking…" : "Unlock"}</button>
        <button type="button" class="m-fl-link" onclick={onforgot} disabled={busy}>Forgot your master password?</button>
      </form>
    {/if}
  </main>
  <footer class="ul-foot">
    {#if fingerprintReady}
      <button type="button" class="ul-switch" onclick={() => (typing = !typing)} disabled={busy}>
        {typing ? `Use ${w.name}` : "Use master password"}
      </button>
    {/if}
    <button type="button" class="ul-out" onclick={notYou} onblur={() => (confirmSignOut = false)} disabled={busy}>
      {confirmSignOut ? "Tap again to sign out of this phone" : "Not you? Sign out"}
    </button>
  </footer>
</div>

<style>
  .ul {
    align-items: center;
    background:
      radial-gradient(ellipse 90% 45% at 50% 100%, rgba(255, 106, 26, 0.14), transparent 70%),
      #0b0b0c;
  }
  .ul-main {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    width: 100%;
    box-sizing: border-box;
    /* 120px on a normal phone, less on short ones. */
    padding: calc(clamp(40px, calc(100vh - 724px), 120px) + var(--sb)) 28px 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
    text-align: center;
  }
  .ul-main > * {
    flex: none;
  }
  .ul-logo {
    width: 84px;
    height: 84px;
    flex: none;
    border-radius: 24px;
  }
  .ul-title {
    margin: 18px 0 0;
    font-size: 32px;
    font-weight: 300;
    letter-spacing: -0.03em;
  }
  .ul-who {
    margin: 0;
    font-size: 16px;
    color: #a1a1aa;
  }
  .ul-print {
    margin-top: clamp(24px, calc(100vh - 780px), 64px);
    width: 104px;
    height: 104px;
    flex: none;
    padding: 0;
    border-radius: 52px;
    border: 1px solid rgba(255, 106, 26, 0.38);
    background: rgba(255, 106, 26, 0.1);
    display: grid;
    place-items: center;
    color: #ff6a1a;
  }
  .ul-hint {
    margin: 6px 0 0;
    font-size: 16px;
    color: #d4d4d8;
  }
  .ul-form {
    width: 100%;
    margin-top: 32px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    text-align: left;
  }
  .ul-note {
    margin: 0 4px;
    font-size: 14px;
    line-height: 1.5;
    color: #a1a1aa;
  }
  .ul-foot {
    width: 100%;
    box-sizing: border-box;
    padding: 0 24px calc(36px + var(--bb));
    display: flex;
    flex-direction: column;
    gap: 10px;
    align-items: center;
  }
  .ul-switch {
    width: 100%;
    min-height: 56px;
    border-radius: 28px;
    border: 1px solid #2a2a2e;
    background: #151517;
    color: #f4f4f5;
    font: 500 16px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .ul-out {
    min-height: 44px;
    border: 0;
    background: none;
    color: #a1a1aa;
    font: 400 14px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
</style>
