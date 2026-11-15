<script lang="ts">
  import type { Snippet } from "svelte";
  import Icon, { type IconName } from "./Icon.svelte";

  let {
    icon,
    tone = "accent",
    children,
  }: { icon: IconName; tone?: "accent" | "quiet"; children: Snippet } = $props();
</script>

<div class="bar" class:quiet={tone === "quiet"} role="status">
  <Icon name={icon} size={15} />
  {@render children()}
</div>

<style>
  .bar {
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
  .quiet {
    background: #1a120c;
    color: var(--accent-soft);
    border-bottom: 1px solid #2a1a10;
  }
</style>
