<script lang="ts">
  import PasswordInput from "./PasswordInput.svelte";
  import { ratePassword, type Rating } from "../lib/api";

  /** A new master password, typed twice, with a strength meter. `ok` is
   *  true once it is strong enough and both copies match. */
  let {
    email,
    password = $bindable(""),
    confirm = $bindable(""),
    ok = $bindable(false),
    disabled = false,
    label = "Master password",
    size = "pw",
  }: {
    email: string;
    password?: string;
    confirm?: string;
    ok?: boolean;
    disabled?: boolean;
    label?: string;
    /** "big" in sign-up and recovery, "pw" in settings. */
    size?: "big" | "pw";
  } = $props();

  let rating = $state<Rating | null>(null);

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

  const tone = $derived(
    !rating ? "" : rating.score >= 4 ? "great" : rating.score === 3 ? "good" : "weak",
  );
  const matches = $derived(confirm.length > 0 && confirm === password);
  $effect(() => {
    ok = rating !== null && rating.acceptable && matches;
  });
</script>

{#snippet meter()}
  {#if rating}
    <div
      class="np-meter {size} {tone}"
      role="meter"
      aria-label="Password strength"
      aria-valuemin={0}
      aria-valuemax={4}
      aria-valuenow={rating.score}
      aria-valuetext={rating.label}
    >
      <div class="np-bars">
        {#each [1, 2, 3, 4] as n (n)}<span class:on={rating.score >= n}></span>{/each}
      </div>
      <span class="np-what">{size === "pw" && rating.guess_time ? `${rating.label} · would take ${rating.guess_time} to guess` : rating.label}</span>
    </div>
    {#if rating.chars < rating.min_chars}
      <span class="np-hint">At least {rating.min_chars} characters · {rating.chars} so far</span>
    {:else if rating.hint && !rating.acceptable}
      <span class="np-hint">{rating.hint}</span>
    {/if}
  {/if}
{/snippet}

<div class="np">
  <div class="np-block">
    <PasswordInput id="new-password" {label} {size} mono={size === "pw"} bind:value={password} autocomplete="new-password" {disabled} />
    {#if size === "big"}{@render meter()}{/if}
  </div>
  <div class="np-block" class:again={size === "big"}>
    <PasswordInput
      id="confirm-password"
      label="Type it again"
      {size}
      mono={size === "pw"}
      bind:value={confirm}
      autocomplete="new-password"
      {disabled}
    />
    {#if confirm.length > 0 && !matches}
      <span class="np-hint">The two passwords don't match yet.</span>
    {/if}
  </div>
  {#if size === "pw"}<div class="np-block">{@render meter()}</div>{/if}
</div>

<style>
  .np {
    display: contents;
  }
  .np-block {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .np-block:empty {
    display: none;
  }
  .np-block.again {
    margin-top: 4px;
  }
  .np-meter {
    display: flex;
    gap: 8px;
    padding: 0 4px;
  }
  .np-meter.big {
    align-items: center;
  }
  .np-meter.pw {
    flex-direction: column;
  }
  .np-bars {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
  .big .np-bars {
    flex: 1;
    height: 6px;
    gap: 3px;
  }
  .pw .np-bars {
    gap: 6px;
  }
  .np-bars span {
    background: #2a2a2e;
    border-radius: 3px;
  }
  .pw .np-bars span {
    height: 5px;
  }
  .np-what {
    font-size: 13px;
  }
  .pw .np-what {
    font-size: 14px;
    color: #d4d4d8;
  }
  .pw .np-bars .on {
    background: #ff6a1a;
  }
  .pw.weak .np-bars .on {
    background: #fca5a5;
  }
  .big.great .np-bars .on {
    background: #86efac;
  }
  .big.great .np-what {
    color: #86efac;
  }
  .big.good .np-bars .on {
    background: #fcd34d;
  }
  .big.good .np-what {
    color: #fcd34d;
  }
  .big.weak .np-bars .on {
    background: #fca5a5;
  }
  .big.weak .np-what {
    color: #fca5a5;
  }
  .np-hint {
    padding: 0 4px;
    font-size: 13px;
    color: #a1a1aa;
  }
</style>
