<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import NewPasswordFields from "../components/NewPasswordFields.svelte";
  import TopNav from "../components/TopNav.svelte";
  import { errorMessage, recoverAccount, type Created } from "../api";

  let {
    knownEmail = null,
    onrecovered,
    onback,
  }: {
    /** The account already on this device, whose address is fixed. */
    knownEmail?: string | null;
    onrecovered: (created: Created) => void;
    onback: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let email = $state(knownEmail ?? "");
  let recoveryKey = $state("");
  let password = $state("");
  let confirm = $state("");
  let ok = $state(false);
  let busy = $state(false);
  let error = $state("");

  const ready = $derived(email.includes("@") && recoveryKey.trim().length > 0 && ok && !busy);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    error = "";
    const [key, pw, again] = [recoveryKey, password, confirm];
    password = "";
    confirm = "";
    try {
      onrecovered(await recoverAccount(email.trim(), key, pw, again));
      recoveryKey = "";
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
    <h1 class="display">Choose a new<br /><span class="hi">master password.</span></h1>
    <p class="lede">
      Your recovery key lets you set a new master password if you've forgotten the old one. You'll
      find it in your Emergency Kit, if you made one.
    </p>
    <ul class="facts">
      <li>Your vaults and everything in them stay as they are.</li>
      <li>Every other device is signed out. Sign in there with the new password.</li>
      <li>You'll get a new recovery key, because this one has now been typed.</li>
    </ul>
  </section>

  <form class="card accent form-card" aria-label="Recover your account" onsubmit={submit}>
    <h2 class="h2">Recover your account</h2>

    <div>
      <label class="label" for="email">Email address</label>
      <div class="field">
        <input
          id="email"
          type="email"
          bind:value={email}
          autocomplete="email"
          spellcheck="false"
          readonly={knownEmail !== null}
          disabled={busy}
        />
      </div>
    </div>

    <div>
      <label class="label" for="recovery-key">Recovery key</label>
      <div class="field">
        <input
          id="recovery-key"
          class="mono"
          type="text"
          bind:value={recoveryKey}
          placeholder="BR1-XXXXXX-XXXXXX-…"
          autocomplete="off"
          spellcheck="false"
          autocapitalize="characters"
          disabled={busy}
        />
      </div>
    </div>

    <NewPasswordFields
      {email}
      bind:password
      bind:confirm
      bind:ok
      disabled={busy}
      label="New master password"
    />

    {#if error}
      <p class="note error" role="alert"><Icon name="alert" />{error}</p>
    {/if}

    <button type="submit" class="btn primary submit" disabled={!ready}>
      {busy ? "Recovering…" : "Set new password"}
    </button>
  </form>
</main>

<style>
  .facts {
    margin: 0;
    padding-left: 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    color: var(--soft);
    font-size: 15px;
  }
  .submit {
    align-self: flex-start;
  }
  input::placeholder {
    color: var(--dim);
  }
  input[readonly] {
    color: var(--muted);
  }
</style>
