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

  /** What still stands between the user and the button below, in plain
   *  words, so a greyed-out button never goes unexplained. */
  const why = $derived.by(() => {
    if (password.length === 0) return "";
    if (!rating) return "Checking how strong it is…";
    if (rating.chars < rating.min_chars) {
      const more = rating.min_chars - rating.chars;
      return `Add ${more} more character${more === 1 ? "" : "s"}. A master password needs at least ${rating.min_chars}, because it is the one thing protecting everything else.`;
    }
    if (!rating.acceptable) {
      return `Still too easy to guess${rating.hint ? `: ${rating.hint.replace(/\.$/, "")}` : ""}. Add another word or two.`;
    }
    if (confirm.length === 0) return "Strong enough. Now type it again below, to make sure there's no typo.";
    if (!matches) return "The two passwords don't match yet. Check the second one for a typo.";
    return "";
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
      {rating.chars} of at least {rating.min_chars} characters
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
</div>
{#if why}<div class="small why" role="status" aria-live="polite">{why}</div>{/if}


<style>
  .why {
    padding: 8px 10px;
    border-radius: 8px;
    background: var(--panel, rgba(255, 255, 255, 0.04));
    color: var(--warn, #fcd34d);
    line-height: 1.45;
  }
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
