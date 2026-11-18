<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import PasswordField from "../components/PasswordField.svelte";
  import TopNav from "../components/TopNav.svelte";
  import { errorMessage, unlock, unlockWithHello, type AppStatus } from "../api";

  let {
    status,
    notice = "",
    onchange,
    onforgot,
  }: {
    status: AppStatus;
    notice?: string;
    onchange: (s: AppStatus) => void;
    onforgot: () => void;
  } = $props();

  const helloReady = $derived(
    status.hello.available && status.hello.enabled && !status.hello.needs_password,
  );

  async function hello() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      onchange(await unlockWithHello());
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

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

<TopNav>
  <span class="small server"><Icon name="globe" size={16} />{status.server}</span>
</TopNav>

<main class="glow page">
  <section class="stack hero" aria-label="Unlock">
    <h1 class="display">Welcome back.<br />Your vaults are <span class="hi">sealed.</span></h1>
    <p class="lede">Enter your master password to open them on this device.</p>
    <form class="form" onsubmit={submit}>
      <PasswordField
        id="master-password"
        label={`Master password for ${status.account?.email ?? "your account"}`}
        bind:value={password}
        disabled={busy}
      />
      {#if error || notice}
        <p class="note error" role="alert"><Icon name="alert" />{error || notice}</p>
      {:else if status.hello.enabled && status.hello.needs_password}
        <p class="small">
          It's been 14 days, so enter your master password this time. Windows Hello works again
          after that.
        </p>
      {/if}
      <div class="actions">
        <button type="submit" class="btn primary" disabled={busy || password.length === 0}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
        {#if helloReady}
          <button type="button" class="btn ghost" disabled={busy} onclick={hello}>
            <Icon name="hello" />Windows Hello
          </button>
        {/if}
      </div>
      <button type="button" class="link start" onclick={onforgot} disabled={busy}>
        Forgot your master password?
      </button>
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
  .start {
    align-self: flex-start;
  }
</style>
