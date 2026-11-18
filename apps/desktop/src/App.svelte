<script lang="ts">
  import {
    appStatus,
    browserStatus,
    errorMessage,
    onBrowserPairing,
    type AppStatus,
    type EmergencyKit as Kit,
    type PairingRequest,
  } from "./lib/api";
  import PairingDialog from "./lib/screens/PairingDialog.svelte";
  import EmergencyKit from "./lib/screens/EmergencyKit.svelte";
  import Recover from "./lib/screens/Recover.svelte";
  import SignIn from "./lib/screens/SignIn.svelte";
  import Signup from "./lib/screens/Signup.svelte";
  import Unlock from "./lib/screens/Unlock.svelte";
  import Vault from "./lib/screens/Vault.svelte";
  import Welcome from "./lib/screens/Welcome.svelte";
  import MobileApp from "./mobile/MobileApp.svelte";

  let status = $state<AppStatus | null>(null);
  let failure = $state("");
  /** Which first-run screen is showing when there is no account yet. */
  let firstRun = $state<"welcome" | "signup" | "signin" | "recover">("welcome");
  /** Recovering the locked account on this device. */
  let recovering = $state(false);
  /** The Emergency Kit, held only until the user confirms they saved it. */
  let kit = $state<Kit | null>(null);
  /** Whether the kit is being shown again from settings. */
  let kitAgain = $state(false);
  /** The step the kit is in sign-up, if it is shown there. */
  let kitStep = $state<string | null>(null);

  /** After a recovery: the new kit, with its new recovery key, to save. */
  function recovered(created: { status: AppStatus; kit: Kit }) {
    kit = created.kit;
    kitAgain = false;
    kitStep = null;
    recovering = false;
    status = created.status;
  }
  /** Why the vaults were locked, shown on the unlock screen. */
  let lockNotice = $state("");

  /** A browser asking to pair, shown over any screen. */
  let pairingRequest = $state<PairingRequest | null>(null);
  $effect(() => {
    const stop = onBrowserPairing((r) => (pairingRequest = r));
    browserStatus().then(
      (b) => (pairingRequest = b.pending),
      () => {},
    );
    return () => {
      stop.then((f) => f(), () => {});
    };
  });

  appStatus().then(
    (s) => (status = s),
    (e: unknown) => (failure = errorMessage(e)),
  );
</script>

{#if status?.mobile}
  <!-- Phones get their own screens, made for one hand and a small screen. -->
  <MobileApp initial={status} />
{:else}
{#if pairingRequest}
  <PairingDialog request={pairingRequest} />
{/if}

<div class="shell">
  {#if failure}
    <p class="note failure" role="alert">{failure}</p>
  {:else if status === null}
    <!-- Starting up; the status arrives within a few milliseconds. -->
  {:else if kit}
    <EmergencyKit
      {kit}
      mobile={status.mobile}
      again={kitAgain}
      step={kitStep}
      ondone={() => {
        kit = null;
        kitAgain = false;
      }}
    />
  {:else if status.account === null}
    {#if firstRun === "signup"}
      <Signup
        oncreated={(created) => {
          kit = created.kit;
          kitStep = "Step 2 of 3";
          status = created.status;
        }}
        onback={() => (firstRun = "welcome")}
      />
    {:else if firstRun === "signin"}
      <SignIn
        onsignedin={(s) => (status = s)}
        onback={() => (firstRun = "welcome")}
        onforgot={() => (firstRun = "recover")}
      />
    {:else if firstRun === "recover"}
      <Recover onrecovered={recovered} onback={() => (firstRun = "signin")} />
    {:else}
      <Welcome
        {status}
        onsignup={() => (firstRun = "signup")}
        onsignin={() => (firstRun = "signin")}
      />
    {/if}
  {:else if status.locked && recovering}
    <Recover
      knownEmail={status.account.email}
      onrecovered={recovered}
      onback={() => (recovering = false)}
    />
  {:else if status.locked}
    <Unlock
      {status}
      notice={lockNotice}
      onforgot={() => (recovering = true)}
      onchange={(s) => {
        lockNotice = "";
        status = s;
      }}
    />
  {:else}
    <Vault
      {status}
      onkit={(k) => {
        kit = k;
        // A new recovery key is shown only once, so ask to confirm it was
        // saved; the kit on its own can be shown again any time.
        kitAgain = k.recovery_key === null;
        kitStep = null;
      }}
      onchange={(s, why) => {
        lockNotice = why ?? "";
        // After signing out, start again from the welcome screen.
        if (s.account === null) firstRun = "welcome";
        status = s;
      }}
    />
  {/if}
</div>
{/if}

<style>
  .shell {
    height: 100%;
    /* Phones draw the app under their status and navigation bars. */
    padding: env(safe-area-inset-top) env(safe-area-inset-right) 0 env(safe-area-inset-left);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .failure {
    margin: 48px;
  }
</style>
