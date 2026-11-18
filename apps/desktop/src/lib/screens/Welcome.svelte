<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import TopNav from "../components/TopNav.svelte";
  import type { AppStatus } from "../api";

  let {
    status,
    onsignup,
    onsignin,
  }: { status: AppStatus; onsignup: () => void; onsignin: () => void } = $props();
</script>

<TopNav>
  <span class="small server"><Icon name="globe" size={16} />{status.server}</span>
</TopNav>

<main class="glow page">
  <section class="stack hero">
    <h1 class="display">Only you can<br />open <span class="hi">your vaults.</span></h1>
    <p class="lede">
      Everything is encrypted on this device before it is synced. Nobody else can read it, not
      even us.
    </p>
    <div class="row">
      <button type="button" class="btn primary" onclick={onsignup}>Create an account</button>
      <button type="button" class="btn ghost" onclick={onsignin}>
        <Icon name="key" />I already have an account
      </button>
    </div>
  </section>
</main>

<style>
  .hero {
    max-width: 640px;
  }
</style>
