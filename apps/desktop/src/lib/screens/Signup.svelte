<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import PasswordField from "../components/PasswordField.svelte";
  import Steps from "../components/Steps.svelte";
  import TopNav from "../components/TopNav.svelte";
  import { createAccount, errorMessage, ratePassword, type Created, type Rating } from "../api";

  let {
    oncreated,
    onback,
  }: { oncreated: (created: Created) => void; onback: () => void } = $props();

  let email = $state("");
  let password = $state("");
  let confirm = $state("");
  let rating = $state<Rating | null>(null);
  let busy = $state(false);
  let error = $state("");

  // Rate the password a moment after typing stops.
  $effect(() => {
    const pw = password;
    const mail = email;
    if (pw.length === 0) {
      rating = null;
      return;
    }
    const timer = setTimeout(() => {
      ratePassword(pw, mail).then(
        (r) => {
          if (password === pw) rating = r;
        },
        () => (rating = null),
      );
    }, 150);
    return () => clearTimeout(timer);
  });

  const matches = $derived(confirm.length > 0 && confirm === password);
  const ready = $derived(
    email.includes("@") && rating !== null && rating.acceptable && matches && !busy,
  );

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

    <div>
      <PasswordField
        id="new-password"
        label="Master password"
        bind:value={password}
        autocomplete="new-password"
        disabled={busy}
      />
      {#if rating}
        <div class="meter-row">
          <div
            class="meter"
            role="meter"
            aria-label="Password strength"
            aria-valuemin={0}
            aria-valuemax={4}
            aria-valuenow={rating.score}
            aria-valuetext={rating.label}
          >
            {#each [1, 2, 3, 4] as n (n)}
              <span class:filled={rating.score >= n} class:weak={rating.score < 3}></span>
            {/each}
          </div>
          <span class="meter-label" class:weak={rating.score < 3}>{rating.label}</span>
        </div>
        <div class="small hint">
          {#if rating.chars < rating.min_chars}
            At least {rating.min_chars} characters · {rating.chars} used
          {:else if rating.hint && !rating.acceptable}
            {rating.hint}
          {:else}
            {rating.chars} characters
          {/if}
        </div>
      {/if}
    </div>

    <div>
      <PasswordField
        id="confirm-password"
        label="Type it again"
        bind:value={confirm}
        autocomplete="new-password"
        disabled={busy}
      />
      {#if confirm.length > 0 && !matches}
        <div class="small hint">The two passwords don't match yet.</div>
      {/if}
    </div>

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
  .meter-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 12px;
    padding: 0 6px;
  }
  .meter {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 4px;
  }
  .meter span {
    height: 4px;
    border-radius: 2px;
    background: var(--line);
  }
  .meter span.filled {
    background: var(--accent);
  }
  .meter span.filled.weak {
    background: var(--muted);
  }
  .meter-label {
    font-size: 13px;
    font-weight: 500;
    color: var(--accent);
    min-width: 72px;
    text-align: right;
  }
  .meter-label.weak {
    color: var(--muted);
  }
  .hint {
    margin-top: 6px;
    padding: 0 6px;
  }
  .submit {
    align-self: flex-start;
  }
</style>
