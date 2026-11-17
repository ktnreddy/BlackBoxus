<script lang="ts">
  import type { Snippet } from "svelte";
  import Icon, { type IconName } from "./Icon.svelte";

  let {
    icon,
    tone = "accent",
    children,
    ondismiss = undefined,
  }: {
    icon: IconName;
    tone?: "accent" | "quiet" | "danger";
    children: Snippet;
    /** Shows a close button that hides the bar. */
    ondismiss?: (() => void) | undefined;
  } = $props();
</script>

<div
  class="bar"
  class:quiet={tone === "quiet"}
  class:danger={tone === "danger"}
  role={tone === "danger" ? "alert" : "status"}
>
  <Icon name={icon} size={15} />
  <span class="text">{@render children()}</span>
  {#if ondismiss}
    <button type="button" class="close" aria-label="Dismiss" onclick={ondismiss}>
      <Icon name="x" size={15} />
    </button>
  {/if}
</div>

<style>
  .bar {
    position: relative;
    height: 36px;
    flex: none;
    background: var(--accent);
    color: var(--accent-ink);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 500;
  }
  .danger {
    background: #3a1414;
    color: #ffc9c9;
    border-bottom: 1px solid #6b2a2a;
    height: auto;
    min-height: 36px;
    padding: 8px 24px;
    text-align: center;
  }
  .text {
    display: inline;
  }
  .close {
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    display: grid;
    place-items: center;
    width: 26px;
    height: 26px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: inherit;
    opacity: 0.75;
    cursor: pointer;
  }
  .close:hover,
  .close:focus-visible {
    opacity: 1;
    background: rgba(255, 255, 255, 0.08);
  }
  .danger {
    padding-right: 52px;
  }
  .quiet {
    background: #1a120c;
    color: var(--accent-soft);
    border-bottom: 1px solid #2a1a10;
  }
</style>
