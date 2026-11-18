<script lang="ts">
  import type { Snippet } from "svelte";
  import Icon from "./Icon.svelte";
  import { back } from "./nav";

  /** A full-screen page with a back button, opened over the tabs. */
  let {
    title,
    backLabel = "Back",
    action,
    children,
    footer,
    form = false,
    tight = false,
    small = false,
  }: {
    title: string;
    /** Form pages (passwords, keys) use wider margins than list pages. */
    form?: boolean;
    /** A title that may wrap gets tighter lines. */
    tight?: boolean;
    /** A longer title, set a size smaller. */
    small?: boolean;
    backLabel?: string;
    action?: Snippet;
    children: Snippet;
    footer?: Snippet;
  } = $props();
</script>

<div class="m-page" class:pg-form={form}>
  <header class="pg-head">
    <button type="button" class="pg-back" aria-label={backLabel} onclick={back}>
      <Icon name="back" size={22} />
    </button>
    <span class="pg-crumb">{backLabel === "Back" ? "" : backLabel}</span>
    <span class="pg-grow"></span>
    {#if action}{@render action()}{/if}
  </header>
  <main class="pg-main m-scroll">
    <h1 class="pg-title" class:pg-tight={tight} class:pg-small={small}>{title}</h1>
    {@render children()}
  </main>
  {#if footer}
    <footer class="pg-foot">{@render footer()}</footer>
  {/if}
</div>

<style>
  .m-page {
    position: fixed;
    inset: 0;
    z-index: 20;
    background: #0b0b0c;
    display: flex;
    flex-direction: column;
  }
  .pg-head {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: calc(48px + var(--sb)) 12px 0;
  }
  .pg-back {
    width: 44px;
    height: 44px;
    flex: none;
    border: 0;
    border-radius: 22px;
    background: none;
    color: #f4f4f5;
    display: grid;
    place-items: center;
    padding: 0;
  }
  .pg-crumb {
    font-size: 17px;
    font-weight: 500;
  }
  .pg-grow {
    flex: 1;
  }
  .pg-main {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 16px 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .pg-title {
    margin: 0 8px;
    font-size: 30px;
    font-weight: 300;
    letter-spacing: -0.02em;
  }
  .pg-main > :global(.m-lede) {
    margin: 0 8px;
    font-size: 15px;
    color: #d4d4d8;
  }
  .pg-form .pg-main {
    padding: 16px 24px 24px;
    gap: 16px;
  }
  .pg-form .pg-title {
    margin: 0;
  }
  .pg-title.pg-small {
    font-size: 28px;
  }
  .pg-title.pg-tight {
    line-height: 1.15;
  }
  .pg-form .pg-main > :global(.m-lede) {
    margin: 0;
  }
  .pg-foot {
    padding: 16px 16px calc(32px + var(--bb));
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .pg-form .pg-foot {
    padding: 16px 24px calc(32px + var(--bb));
  }
</style>
