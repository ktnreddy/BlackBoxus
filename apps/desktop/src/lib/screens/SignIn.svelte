<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import PasswordField from "../components/PasswordField.svelte";
  import TopNav from "../components/TopNav.svelte";
  import { errorMessage, signIn, type AppStatus } from "../api";

  let {
    onsignedin,
    onback,
  }: { onsignedin: (status: AppStatus) => void; onback: () => void } = $props();

  let email = $state("");
  let secretKey = $state("");
  let password = $state("");
  let busy = $state(false);
  let error = $state("");

  const ready = $derived(
    email.includes("@") && secretKey.trim().length > 0 && password.length > 0 && !busy,
  );

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    error = "";
    const [key, pw] = [secretKey, password];
    password = "";
    try {
      onsignedin(await signIn(email.trim(), key, pw));
      secretKey = "";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<TopNav>
  <button type="button" class="btn ghost sm" onclick={onback} disabled={busy}>
    <Icon name="arrowLeft" size={15} />Back
  </button>
</TopNav>

<main class="glow page split">
  <section class="stack">
    <h1 class="display">Sign in on<br /><span class="hi">this computer.</span></h1>
    <p class="lede">
      You'll need your Emergency Kit. The Secret Key in it is stored on this computer, so you only
      type it once.
    </p>
  </section>

  <form class="card accent form-card" aria-label="Sign in" onsubmit={submit}>
    <h2 class="h2">Sign in</h2>

    <div>
      <label class="label" for="email">Email address</label>
      <div class="field">
        <input
          id="email"
          type="email"
          bind:value={email}
          autocomplete="email"
          spellcheck="false"
          disabled={busy}
        />
      </div>
    </div>

    <div>
      <label class="label" for="secret-key">Secret Key</label>
      <div class="field">
        <input
          id="secret-key"
          class="mono"
          type="text"
          bind:value={secretKey}
          placeholder="B1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX"
          autocomplete="off"
          spellcheck="false"
          autocapitalize="characters"
          disabled={busy}
        />
      </div>
    </div>

    <PasswordField id="password" label="Master password" bind:value={password} disabled={busy} />

    {#if error}
      <p class="note error" role="alert"><Icon name="alert" />{error}</p>
    {/if}

    <button type="submit" class="btn primary submit" disabled={!ready}>
      {busy ? "Signing in…" : "Sign in"}
    </button>
  </form>
</main>

<style>
  .submit {
    align-self: flex-start;
  }
  input::placeholder {
    color: var(--dim);
  }
</style>
