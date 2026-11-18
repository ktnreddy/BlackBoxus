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
    min-width: 0;
  }
  @media (max-width: 760px) {
    .nav {
      height: 60px;
      padding: 0 18px;
    }
    /* The server name is in Settings; the logo and buttons fit. */
    .right :global(.server) {
      display: none;
    }
  }
</style>
