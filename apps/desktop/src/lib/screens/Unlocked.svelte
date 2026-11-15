<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import StatusBar from "../components/StatusBar.svelte";
  import TopNav from "../components/TopNav.svelte";
  import { lock, type AppStatus } from "../api";

  let { status, onchange }: { status: AppStatus; onchange: (s: AppStatus) => void } = $props();
</script>

<StatusBar icon="shield">Signed in and unlocked</StatusBar>

<TopNav>
  <span class="small">{status.account?.email}</span>
  <button type="button" class="btn ghost sm" onclick={async () => onchange(await lock())}>
    <Icon name="lock" size={15} />Lock now
  </button>
</TopNav>

<main class="glow page">
  <section class="stack">
    <h1 class="display">Your vaults are <span class="hi">open.</span></h1>
    <p class="lede">Your vaults and items will appear here.</p>
  </section>
</main>
