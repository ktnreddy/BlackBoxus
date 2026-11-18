<script lang="ts">
  import type { Snippet } from "svelte";
  import { back } from "./nav";

  /** A panel that slides up from the bottom. Close it with `back()`.
   *  `gap` is the space between its rows: 6px for lists, 4px for actions
   *  and choices. `actions` gives the handle more room above action rows. */
  let {
    label,
    gap = 6,
    actions = false,
    children,
  }: { label: string; gap?: 4 | 6; actions?: boolean; children: Snippet } = $props();
</script>

<div class="layer">
  <button type="button" class="scrim" aria-label="Close" onclick={back}></button>
  <div class="sheet" class:tight={gap === 4} class:actions role="dialog" aria-modal="true" aria-label={label}>
    <span class="grab" aria-hidden="true"></span>
    {@render children()}
  </div>
</div>

<style>
  .layer {
    position: fixed;
    inset: 0;
    z-index: 30;
  }
  .scrim {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    border: 0;
    background: rgba(5, 5, 6, 0.6);
    animation: fade 0.15s ease-out;
  }
  .sheet {
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    max-height: 85vh;
    overflow-y: auto;
    padding: 10px 16px calc(32px + var(--bb));
    border-radius: 28px 28px 0 0;
    background: #151517;
    border-top: 1px solid #2a2a2e;
    display: flex;
    flex-direction: column;
    gap: 6px;
    animation: rise 0.2s ease-out;
  }
  .sheet.tight {
    gap: 4px;
  }
  .grab {
    align-self: center;
    width: 40px;
    height: 4px;
    border-radius: 2px;
    background: #3f3f46;
    margin-bottom: 10px;
  }
  .actions .grab {
    margin-bottom: 12px;
  }
  @keyframes rise {
    from {
      transform: translateY(40px);
      opacity: 0.4;
    }
  }
  @keyframes fade {
    from {
      opacity: 0;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .scrim,
    .sheet {
      animation: none;
    }
  }
</style>
