<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import PasswordField from "../components/PasswordField.svelte";
  import StatusBar from "../components/StatusBar.svelte";
  import TopNav from "../components/TopNav.svelte";
  import { errorMessage, unlock, type AppStatus } from "../api";

  let { status, onchange }: { status: AppStatus; onchange: (s: AppStatus) => void } = $props();

  let password = $state("");
  let busy = $state(false);
  let error = $state("");

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || password.length === 0) return;
    busy = true;
    error = "";
    const typed = password;
    // Clear the field straight away so the password does not linger in
    // the page; the Rust side wipes its copy after use.
    password = "";
    try {
      onchange(await unlock(typed));
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<StatusBar icon="lock" tone="quiet">
  Locked. Everything on this computer stays encrypted until you unlock.
</StatusBar>

<TopNav>
  <span class="small server"><Icon name="globe" size={16} />{status.server}</span>
</TopNav>

<main class="glow page">
  <section class="stack hero" aria-label="Unlock">
    <h1 class="display">Welcome back.<br />Your vaults are <span class="hi">sealed.</span></h1>
    <p class="lede">Enter your master password to open them on this computer.</p>
    <form class="form" onsubmit={submit}>
      <PasswordField
        id="master-password"
        label={`Master password for ${status.account?.email ?? "your account"}`}
        bind:value={password}
        disabled={busy}
      />
      {#if error}
        <p class="note error" role="alert"><Icon name="alert" />{error}</p>
      {/if}
      <div class="actions">
        <button type="submit" class="btn primary" disabled={busy || password.length === 0}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
        <!-- Windows Hello arrives with device unlocking. -->
        <button type="button" class="btn ghost" disabled><Icon name="hello" />Windows Hello</button>
      </div>
    </form>
  </section>
</main>

<style>
  .hero {
    width: min(100%, 560px);
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 460px;
  }
  .actions {
    display: flex;
    gap: 12px;
  }
</style>
