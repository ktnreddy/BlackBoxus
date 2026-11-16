<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import TopNav from "../components/TopNav.svelte";
  import type { EmergencyKit } from "../api";

  let {
    kit,
    again = false,
    ondone,
  }: { kit: EmergencyKit; again?: boolean; ondone: () => void } = $props();

  let saved = $state(false);
  const created = new Date().toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
</script>

<TopNav>
  {#if again}
    <button type="button" class="btn ghost sm" onclick={ondone}>Done</button>
  {:else}
    <span class="small">Step 2 of 3</span>
  {/if}
</TopNav>

<main class="glow page split">
  <section class="stack">
    <h1 class="display">
      {again ? "Your" : "Save your"}<br /><span class="hi">Emergency Kit.</span>
    </h1>
    <p class="lede">
      Your Secret Key and your master password together unlock your account on a new device. Keep
      this kit somewhere safe and offline, like a drawer at home.
    </p>
    <ul class="checks">
      <li><span class="good"><Icon name="check" /></span>Print it, or save it as a PDF on a USB drive</li>
      <li><span class="bad"><Icon name="x" /></span>Don't email it to yourself or keep it in the cloud</li>
      <li><span class="good"><Icon name="check" /></span>Your master password is never in the kit</li>
    </ul>
    <div class="row">
      <button type="button" class="btn primary" onclick={() => window.print()}>
        <Icon name="print" />Print or save as PDF
      </button>
    </div>
    {#if !again}
    <div class="rule"></div>
    <div class="row confirm">
      <label class="check">
        <input type="checkbox" bind:checked={saved} />
        I've saved my Emergency Kit
      </label>
      <button type="button" class="btn ghost sm" disabled={!saved} onclick={ondone}>Continue</button>
    </div>
    {/if}
  </section>

  <article class="kit" aria-label="Emergency Kit">
    <div class="kit-bar"></div>
    <div class="kit-body">
      <div class="kit-head">
        <span class="kit-logo"><span class="kit-mark"><i></i></span>BlackBoxus</span>
        <span class="kit-muted">{again ? "Printed" : "Created"} {created}</span>
      </div>
      <h2 class="kit-title">Emergency Kit</h2>
      <dl>
        <div><dt>Email</dt><dd class="selectable">{kit.email}</dd></div>
        <div><dt>Server</dt><dd class="selectable">{kit.server}</dd></div>
        <div><dt>Secret Key</dt><dd class="mono key selectable">{kit.secret_key}</dd></div>
        <div>
          <dt>Master password</dt>
          <dd class="write-in"></dd>
          <dd class="kit-muted">Write it here by hand only if you choose to.</dd>
        </div>
      </dl>
    </div>
  </article>
</main>

<style>
  .checks {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .checks li {
    display: flex;
    gap: 12px;
    align-items: center;
    font-size: 15px;
    color: var(--soft);
  }
  .good {
    color: var(--good);
    display: flex;
  }
  .bad {
    color: var(--accent);
    display: flex;
  }
  .confirm {
    gap: 24px;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 15px;
    cursor: pointer;
  }
  .check input {
    width: 20px;
    height: 20px;
    margin: 0;
    accent-color: var(--accent);
  }

  .kit {
    background: #f4f1ec;
    color: #141416;
    border-radius: var(--radius-card);
    overflow: hidden;
    box-shadow: 0 40px 80px -30px rgba(255, 106, 26, 0.35);
  }
  .kit-bar {
    height: 8px;
    background: var(--accent);
  }
  .kit-body {
    padding: 30px 34px 32px;
  }
  .kit-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .kit-logo {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 17px;
    font-weight: 600;
    letter-spacing: -0.02em;
  }
  .kit-mark {
    width: 24px;
    height: 24px;
    border-radius: 7px;
    background: #141416;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .kit-mark i {
    width: 9px;
    height: 9px;
    border-radius: 2px;
    background: var(--accent);
    display: block;
  }
  .kit-muted {
    font-size: 12px;
    color: #6b6660;
  }
  .kit-title {
    margin: 18px 0 14px;
    font-size: 28px;
    font-weight: 300;
    letter-spacing: -0.03em;
  }
  dl {
    margin: 0;
  }
  dl > div {
    padding: 14px 0;
    border-top: 1px solid #ddd8cf;
  }
  dt {
    font-size: 12px;
    color: #6b6660;
  }
  dd {
    margin: 4px 0 0;
    font-size: 15px;
    overflow-wrap: anywhere;
  }
  .key {
    font-size: 17px;
    font-weight: 500;
    letter-spacing: 0.02em;
  }
  .write-in {
    height: 40px;
    border-bottom: 1px dashed #b9b2a7;
  }

  /* Printing shows only the kit, on white paper. */
  @media print {
    :global(body) {
      background: #fff;
    }
    :global(.bar),
    :global(.nav),
    section {
      display: none !important;
    }
    .page {
      display: block;
      padding: 0;
      background: none;
    }
    .kit {
      box-shadow: none;
      background: #fff;
      border: 1px solid #ddd8cf;
      max-width: 560px;
      margin: 0 auto;
    }
  }
</style>
