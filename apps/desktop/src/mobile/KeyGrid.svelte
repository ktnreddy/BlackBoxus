<script lang="ts">
  /** A Secret Key, as one key whose dashes mark groups to copy one at a
   *  time; or a recovery key, as numbered words. */
  let { text, numbered = false }: { text: string; numbered?: boolean } = $props();

  const groups = $derived(text.split("-").filter((g) => g !== ""));
</script>

{#if numbered}
  <div class="kg numbered">
    {#each groups as g, i (i)}
      <span class="kg-item"><span class="kg-n">{i + 1}</span><span class="kg-word">{g}</span></span>
    {/each}
  </div>
{:else}
  <!-- One key: a line break may only fall after a dash, never inside a group. -->
  <p class="kg-one" aria-label="Secret Key {groups.join(' dash ')}">
    {#each groups as g, i (i)}<span class="kg-group">{g}{#if i < groups.length - 1}<span class="kg-dash">-</span>{/if}</span>{/each}
  </p>
{/if}

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
  .kg-one {
    margin: 0;
    padding: 14px 12px;
    border-radius: 14px;
    background: #1c1c1f;
    font-family: var(--font-mono);
    font-size: 21px;
    line-height: 1.6;
    letter-spacing: 1px;
    text-align: center;
    overflow-wrap: normal;
    user-select: text;
    -webkit-user-select: text;
  }
  .kg-group {
    display: inline-block;
    white-space: nowrap;
  }
  .kg-dash {
    color: #71717a;
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
