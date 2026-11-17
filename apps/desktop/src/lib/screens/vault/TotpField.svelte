<script lang="ts">
  import { errorMessage, totpCode, type TotpCode } from "../../api";

  let {
    vault,
    item,
    index,
    code = $bindable(),
    owner = undefined,
  }: {
    vault: string;
    item: string;
    index: number;
    code?: string | undefined;
    owner?: string | undefined;
  } = $props();

  let current = $state<TotpCode | null>(null);
  let error = $state("");

  // Ask for the code every second; it's computed in Rust from the secret,
  // which never comes to the window.
  $effect(() => {
    const [v, i, n] = [vault, item, index];
    let stopped = false;
    const tick = () =>
      totpCode(v, i, n, owner).then(
        (c) => {
          if (stopped) return;
          current = c;
          code = c.code;
        },
        (e: unknown) => (error = errorMessage(e)),
      );
    tick();
    const timer = setInterval(tick, 1000);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  });

  const shown = $derived(
    current
      ? current.code.length === 6
        ? `${current.code.slice(0, 3)} ${current.code.slice(3)}`
        : `${current.code.slice(0, 4)} ${current.code.slice(4)}`
      : "",
  );
  /** Circumference of the countdown ring. */
  const RING = 2 * Math.PI * 9;
  const offset = $derived(current ? RING * (1 - current.remaining / current.period) : 0);
</script>

{#if error}
  <span class="small">{error}</span>
{:else}
  <span class="totp">
    <span class="mono code selectable" aria-live="off">{shown}</span>
    {#if current}
      <svg width="22" height="22" viewBox="0 0 22 22" aria-label={`${current.remaining} seconds left`}>
        <circle cx="11" cy="11" r="9" fill="none" stroke="#2a2a2e" stroke-width="2.5" />
        <circle
          cx="11"
          cy="11"
          r="9"
          fill="none"
          stroke={current.remaining <= 5 ? "#ff6b6b" : "#ff6a1a"}
          stroke-width="2.5"
          stroke-linecap="round"
          stroke-dasharray={RING}
          stroke-dashoffset={offset}
          transform="rotate(-90 11 11)"
        />
      </svg>
      <span class="small secs">{current.remaining}s</span>
    {/if}
  </span>
{/if}

<style>
  .totp {
    display: inline-flex;
    align-items: center;
    gap: 10px;
  }
  .code {
    font-size: 22px;
    letter-spacing: 0.04em;
    color: var(--text);
  }
  .secs {
    min-width: 26px;
  }
</style>
