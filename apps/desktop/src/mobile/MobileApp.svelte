<script lang="ts">
  import "@fontsource-variable/dm-sans/opsz.css";
  import "./mobile.css";
  import FirstRun from "./FirstRun.svelte";
  import FingerprintOffer from "./FingerprintOffer.svelte";
  import Kit from "./Kit.svelte";
  import Main from "./Main.svelte";
  import Unlock from "./Unlock.svelte";
  import Page from "./Page.svelte";
  import NewPassword from "./NewPassword.svelte";
  import PasswordInput from "./PasswordInput.svelte";
  import { opened, reset } from "./nav";
  import { startIOS } from "./ios";
  import {
    errorMessage,
    recoverAccount,
    type AppStatus,
    type Created,
    type EmergencyKit,
  } from "../lib/api";

  /** The phone app: the same Rust commands as the desktop, with screens
   *  made for one hand and a small screen. */
  let { initial }: { initial: AppStatus } = $props();

  // svelte-ignore state_referenced_locally
  let status = $state<AppStatus>(initial);
  $effect(() => {
    if (status.platform === "ios") startIOS();
  });
  /** The Emergency Kit, held only until the user confirms they wrote it down. */
  let kit = $state<EmergencyKit | null>(null);
  let kitAgain = $state(false);
  let kitStep = $state<string | null>(null);
  /** Offer fingerprint unlock once, right after sign-up or sign-in. */
  let offerFingerprint = $state(false);
  /** Whether the offer is step 4 of sign-up, or follows a sign-in. */
  let offerInSignup = $state(false);
  /** Fingerprint unlock was turned off because the phone's fingerprints
   *  changed: offer it again, with that reason, once unlocked. */
  let fingerprintChanged = $state(false);
  let lockNotice = $state("");

  function created(c: Created, step: string | null) {
    reset();
    kit = c.kit;
    kitAgain = false;
    kitStep = step;
    status = c.status;
  }

  function signedIn(s: AppStatus) {
    reset();
    status = s;
    offerInSignup = false;
    offerFingerprint = s.hello.available && !s.hello.enabled;
  }

  function kitDone() {
    const wasNew = !kitAgain;
    kit = null;
    kitAgain = false;
    if (wasNew) {
      offerInSignup = kitStep !== null;
      offerFingerprint = status.hello.available && !status.hello.enabled;
    }
  }

  // Recovering a locked account on this phone.
  let recovering = $state(false);
  let recoveryKey = $state("");
  let password = $state("");
  let confirm = $state("");
  let ok = $state(false);
  let busy = $state(false);
  let error = $state("");

  function startRecovery() {
    recovering = true;
    error = "";
    opened(() => (recovering = false));
  }

  async function recover(event: SubmitEvent) {
    event.preventDefault();
    const email = status.account?.email;
    if (!email || busy || recoveryKey.trim() === "" || !ok) return;
    busy = true;
    error = "";
    const [key, pw, again] = [recoveryKey, password, confirm];
    password = "";
    confirm = "";
    try {
      const c = await recoverAccount(email, key, pw, again);
      recoveryKey = "";
      recovering = false;
      created(c, null);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="m-root">
  {#if kit}
    <Kit {kit} again={kitAgain} step={kitStep} ondone={kitDone} />
  {:else if status.account === null}
    <FirstRun
      {status}
      oncreated={(c) => created(c, "Step 3 of 4")}
      onsignedin={signedIn}
      onrecovered={(c) => created(c, null)}
    />
  {:else if offerFingerprint && !status.locked}
    <FingerprintOffer
      {status}
      signup={offerInSignup}
      changed={fingerprintChanged}
      ondone={(s) => {
        offerFingerprint = false;
        fingerprintChanged = false;
        if (s) status = s;
      }}
    />
  {:else if status.locked}
    <Unlock
      {status}
      notice={lockNotice}
      onforgot={startRecovery}
      onfingerprintreset={() => (fingerprintChanged = true)}
      onchange={(s) => {
        lockNotice = "";
        status = s;
        if (!s.locked && fingerprintChanged) {
          offerInSignup = false;
          offerFingerprint = s.hello.available && !s.hello.enabled;
          if (!offerFingerprint) fingerprintChanged = false;
        }
      }}
    />
    {#if recovering}
      <Page title="Forgot your master password?">
        <p class="m-lede">
          Your recovery key from the Emergency Kit lets you choose a new master password. Your
          vaults stay as they are, and other devices are signed out.
        </p>
        <form class="form" onsubmit={recover}>
          <PasswordInput id="lr-key" label="Recovery key" bind:value={recoveryKey} autocomplete="off" disabled={busy} />
          <NewPassword
            email={status.account.email}
            bind:password
            bind:confirm
            bind:ok
            disabled={busy}
            label="New master password"
          />
          {#if error}<p class="m-error" role="alert">{error}</p>{/if}
          <button type="submit" class="m-btn" disabled={busy || recoveryKey.trim() === "" || !ok}>
            {busy ? "Recovering…" : "Continue and set the new password"}
          </button>
        </form>
      </Page>
    {/if}
  {:else}
    <Main
      {status}
      onkit={(k) => {
        kit = k;
        kitAgain = k.recovery_key === null;
        kitStep = null;
      }}
      onchange={(s, why) => {
        reset();
        lockNotice = why ?? "";
        status = s;
      }}
    />
  {/if}
</div>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
</style>
