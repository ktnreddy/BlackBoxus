<script lang="ts">
  import Icon from "./Icon.svelte";

  /** The sign-up header. The back arrow has its own row, so the progress
   *  bar sits in the same place on every step, whether or not there is a
   *  step to go back to (steps 3 and 4 come after the account exists). */
  let { step, onback }: { step: number; onback?: () => void } = $props();
</script>

<header class="sh">
  <div class="sh-top">
    {#if onback}
      <button type="button" class="sh-back" aria-label="Back" onclick={onback}><Icon name="back" size={22} /></button>
    {/if}
  </div>
  <div class="sh-segs" role="progressbar" aria-label="Sign-up progress" aria-valuemin={1} aria-valuemax={4} aria-valuenow={step}>
    {#each [1, 2, 3, 4] as n (n)}<span class:on={n <= step}></span>{/each}
  </div>
</header>

<style>
  .sh {
    padding: calc(48px + var(--sb)) 0 0;
    flex: none;
  }
  .sh-top {
    height: 44px;
    padding: 0 12px;
    display: flex;
    align-items: center;
  }
  .sh-back {
    width: 44px;
    height: 44px;
    flex: none;
    padding: 0;
    border-radius: 22px;
    border: 0;
    background: none;
    color: #f4f4f5;
    display: grid;
    place-items: center;
  }
  .sh-segs {
    margin: 8px 24px 0;
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 6px;
  }
  .sh-segs span {
    height: 4px;
    border-radius: 2px;
    background: #2a2a2e;
  }
  .sh-segs .on {
    background: #ff6a1a;
  }
</style>
