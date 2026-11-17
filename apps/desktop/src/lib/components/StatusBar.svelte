<script lang="ts">
  import type { Snippet } from "svelte";
  import Icon, { type IconName } from "./Icon.svelte";

  let {
    icon,
    tone = "accent",
    children,
  }: { icon: IconName; tone?: "accent" | "quiet" | "danger"; children: Snippet } = $props();
</script>

<div
  class="bar"
  class:quiet={tone === "quiet"}
  class:danger={tone === "danger"}
  role={tone === "danger" ? "alert" : "status"}
>
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
  .danger {
    background: #3a1414;
    color: #ffc9c9;
    border-bottom: 1px solid #6b2a2a;
    height: auto;
    min-height: 36px;
    padding: 8px 24px;
    text-align: center;
  }
  .quiet {
    background: #1a120c;
    color: var(--accent-soft);
    border-bottom: 1px solid #2a1a10;
  }
</style>
