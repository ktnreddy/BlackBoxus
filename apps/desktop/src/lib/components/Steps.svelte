<script lang="ts">
  import Icon from "./Icon.svelte";

  let { steps, active }: { steps: { title: string; detail: string }[]; active: number } = $props();
</script>

<ol class="steps">
  {#each steps as step, i (step.title)}
    {@const n = i + 1}
    <li aria-current={n === active ? "step" : undefined}>
      <span class="num" class:on={n === active} class:done={n < active}>
        {#if n < active}<Icon name="check" size={15} />{:else}{n}{/if}
      </span>
      <div>
        <div class="title" class:current={n === active}>{step.title}</div>
        <div class="small detail">{step.detail}</div>
      </div>
    </li>
  {/each}
</ol>

<style>
  .steps {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 22px;
  }
  li {
    display: flex;
    gap: 16px;
  }
  .num {
    width: 30px;
    height: 30px;
    border-radius: 999px;
    border: 1px solid var(--line);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    font-weight: 500;
    color: var(--muted);
    flex: none;
  }
  .num.on {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-ink);
  }
  .num.done {
    border-color: var(--accent-line);
    color: var(--accent);
  }
  .title {
    font-size: 16px;
    font-weight: 500;
    color: var(--muted);
  }
  .title.current {
    color: var(--text);
  }
  .detail {
    margin-top: 4px;
  }
</style>
