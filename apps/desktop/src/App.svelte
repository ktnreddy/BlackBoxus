<script lang="ts">
  import { appStatus, errorMessage, type AppStatus, type EmergencyKit as Kit } from "./lib/api";
  import EmergencyKit from "./lib/screens/EmergencyKit.svelte";
  import SignIn from "./lib/screens/SignIn.svelte";
  import Signup from "./lib/screens/Signup.svelte";
  import Unlock from "./lib/screens/Unlock.svelte";
  import Vault from "./lib/screens/Vault.svelte";
  import Welcome from "./lib/screens/Welcome.svelte";

  let status = $state<AppStatus | null>(null);
  let failure = $state("");
  /** Which first-run screen is showing when there is no account yet. */
  let firstRun = $state<"welcome" | "signup" | "signin">("welcome");
  /** The Emergency Kit, held only until the user confirms they saved it. */
  let kit = $state<Kit | null>(null);
  /** Why the vaults were locked, shown on the unlock screen. */
  let lockNotice = $state("");

  appStatus().then(
    (s) => (status = s),
    (e: unknown) => (failure = errorMessage(e)),
  );
</script>

<div class="shell">
  {#if failure}
    <p class="note failure" role="alert">{failure}</p>
  {:else if status === null}
    <!-- Starting up; the status arrives within a few milliseconds. -->
  {:else if kit}
    <EmergencyKit {kit} ondone={() => (kit = null)} />
  {:else if status.account === null}
    {#if firstRun === "signup"}
      <Signup
        oncreated={(created) => {
          kit = created.kit;
          status = created.status;
        }}
        onback={() => (firstRun = "welcome")}
      />
    {:else if firstRun === "signin"}
      <SignIn onsignedin={(s) => (status = s)} onback={() => (firstRun = "welcome")} />
    {:else}
      <Welcome
        {status}
        onsignup={() => (firstRun = "signup")}
        onsignin={() => (firstRun = "signin")}
      />
    {/if}
  {:else if status.locked}
    <Unlock
      {status}
      notice={lockNotice}
      onchange={(s) => {
        lockNotice = "";
        status = s;
      }}
    />
  {:else}
    <Vault
      {status}
      onchange={(s, why) => {
        lockNotice = why ?? "";
        status = s;
      }}
    />
  {/if}
</div>

<style>
  .shell {
    height: 100%;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .failure {
    margin: 48px;
  }
</style>
