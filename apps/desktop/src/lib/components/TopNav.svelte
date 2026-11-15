<script lang="ts">
  import type { Snippet } from "svelte";
  import Logo from "./Logo.svelte";

  let { children }: { children?: Snippet } = $props();
</script>

<nav class="nav" aria-label="Top">
  <Logo />
  <div class="right">{@render children?.()}</div>
</nav>

<style>
  .nav {
    height: 68px;
    flex: none;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 48px;
  }
  .right {
    display: flex;
    align-items: center;
    gap: 16px;
  }
</style>
