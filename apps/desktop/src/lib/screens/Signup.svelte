<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import NewPasswordFields from "../components/NewPasswordFields.svelte";
  import Steps from "../components/Steps.svelte";
  import TopNav from "../components/TopNav.svelte";
  import { createAccount, errorMessage, type Created } from "../api";

  let {
    oncreated,
    onback,
  }: { oncreated: (created: Created) => void; onback: () => void } = $props();

  let email = $state("");
  let password = $state("");
  let confirm = $state("");
  let ok = $state(false);
  let busy = $state(false);
  let error = $state("");

  const ready = $derived(email.includes("@") && ok && !busy);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    error = "";
    const [pw, again] = [password, confirm];
    password = "";
    confirm = "";
    try {
      oncreated(await createAccount(email.trim(), pw, again));
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
    <h1 class="display">Only you can<br />open <span class="hi">your vaults.</span></h1>
    <Steps
      active={1}
      steps={[
        {
          title: "Choose a master password",
          detail: "It never leaves this computer. Nobody can reset it, not even us.",
        },
        {
          title: "Save your Emergency Kit",
          detail: "It holds your Secret Key, which you need to sign in on a new device.",
        },
        {
          title: "Add your first passwords",
          detail: "Everything is encrypted on this computer before it is synced.",
        },
      ]}
    />
  </section>

  <form class="card accent form-card" aria-label="Create your account" onsubmit={submit}>
    <div class="form-head">
      <h2 class="h2">Create your account</h2>
      <span class="small">Step 1 of 3</span>
    </div>

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

    <NewPasswordFields {email} bind:password bind:confirm bind:ok disabled={busy} />

    <div class="note">
      <Icon name="alert" />
      <span>
        If you forget your master password and lose your Emergency Kit, your data cannot be
        recovered.
      </span>
    </div>

    {#if error}
      <p class="note error" role="alert"><Icon name="alert" />{error}</p>
    {/if}

    <button type="submit" class="btn primary submit" disabled={!ready}>
      {busy ? "Creating your account…" : "Continue"}
    </button>
  </form>
</main>

<style>
  .submit {
    align-self: flex-start;
  }
</style>
