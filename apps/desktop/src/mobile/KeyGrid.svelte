<script lang="ts">
  /** A Secret Key or recovery key, split into its groups so it's easy to
   *  copy onto paper. */
  let { text, numbered = false }: { text: string; numbered?: boolean } = $props();

  const groups = $derived(text.split("-").filter((g) => g !== ""));
</script>

<div class="kg" class:numbered>
  {#each groups as g, i (i)}
    {#if numbered}
      <span class="kg-item"><span class="kg-n">{i + 1}</span><span class="kg-word">{g}</span></span>
    {:else}
      <span class="kg-tile">{g}</span>
    {/if}
  {/each}
</div>

<style>
  .kg {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    font-family: var(--font-mono);
    font-size: 21px;
    text-align: center;
    user-select: text;
    -webkit-user-select: text;
  }
  .kg-tile {
    padding: 10px 0;
    border-radius: 12px;
    background: #1c1c1f;
  }
  .kg.numbered {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px 16px;
    font-family: inherit;
    font-size: 16px;
    text-align: left;
  }
  .kg-item {
    display: flex;
    gap: 8px;
    align-items: baseline;
  }
  .kg-n {
    width: 14px;
    flex: none;
    font-size: 12px;
    color: #71717a;
  }
  .kg-word {
    font-family: var(--font-mono);
    font-size: 18px;
    letter-spacing: 1px;
  }
</style>
