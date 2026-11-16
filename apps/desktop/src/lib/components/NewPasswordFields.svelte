<script lang="ts">
  import PasswordField from "./PasswordField.svelte";
  import { ratePassword, type Rating } from "../api";

  /** A new master password, typed twice, with a strength meter. `ok` is
   *  true once it is strong enough and both copies match. */
  let {
    email,
    password = $bindable(""),
    confirm = $bindable(""),
    ok = $bindable(false),
    disabled = false,
    label = "Master password",
  }: {
    email: string;
    password?: string;
    confirm?: string;
    ok?: boolean;
    disabled?: boolean;
    label?: string;
  } = $props();

  let rating = $state<Rating | null>(null);

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
  $effect(() => {
    ok = rating !== null && rating.acceptable && matches;
  });
</script>

<div>
  <PasswordField
    id="new-password"
    {label}
    bind:value={password}
    autocomplete="new-password"
    {disabled}
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
    {disabled}
  />
  {#if confirm.length > 0 && !matches}
    <div class="small hint">The two passwords don't match yet.</div>
  {/if}
</div>


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
</style>
