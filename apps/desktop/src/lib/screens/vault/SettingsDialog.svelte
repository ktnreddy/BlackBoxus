<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import { errorMessage, helloDisable, helloEnable, type AppStatus } from "../../api";

  let {
    status,
    onchange,
    onclose,
    onnotice,
  }: {
    status: AppStatus;
    onchange: (s: AppStatus) => void;
    onclose: () => void;
    onnotice: (text: string) => void;
  } = $props();

  let busy = $state(false);
  let error = $state("");

  async function toggleHello() {
    busy = true;
    error = "";
    try {
      const next = status.hello.enabled ? await helloDisable() : await helloEnable();
      onchange(next);
      onnotice(
        next.hello.enabled ? "Windows Hello unlock is on." : "Windows Hello unlock is off.",
      );
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Escape") onclose();
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop" role="presentation">
  <div class="card accent dialog" role="dialog" aria-modal="true" aria-labelledby="settings-title">
    <div class="top">
      <h1 id="settings-title" class="title">Settings</h1>
      <button type="button" class="icon-btn" aria-label="Close" onclick={onclose}>
        <Icon name="x" />
      </button>
    </div>

    <div class="setting">
      <div class="text">
        <span class="name"><Icon name="hello" size={18} />Unlock with Windows Hello</span>
        <span class="small">
          {#if status.hello.available}
            Use your face, fingerprint or PIN instead of typing your master password. You'll still
            enter the master password every 14 days. The key stays in this computer's security chip
            and never leaves it.
          {:else}
            Windows Hello isn't set up on this computer. Turn it on in Windows Settings, under
            Accounts, Sign-in options.
          {/if}
        </span>
      </div>
      <label class="switch">
        <span class="visually-hidden">Unlock with Windows Hello</span>
        <input
          type="checkbox"
          role="switch"
          checked={status.hello.enabled}
          disabled={busy || (!status.hello.available && !status.hello.enabled)}
          onchange={toggleHello}
        />
      </label>
    </div>

    {#if error}
      <p class="note" role="alert"><Icon name="alert" />{error}</p>
    {/if}

    <div class="row actions">
      <button type="button" class="btn primary" onclick={onclose}>Done</button>
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(5, 5, 6, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
  }
  .dialog {
    width: min(560px, calc(100vw - 48px));
    padding: 32px 36px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    box-shadow: 0 50px 120px -40px rgba(0, 0, 0, 0.9);
  }
  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .title {
    margin: 0;
    font-size: 28px;
    font-weight: 300;
    letter-spacing: -0.02em;
  }
  .setting {
    display: flex;
    gap: 20px;
    align-items: flex-start;
    justify-content: space-between;
    padding: 18px 0;
    border-top: 1px solid var(--hair);
    border-bottom: 1px solid var(--hair);
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .name {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 16px;
    font-weight: 500;
  }
  .switch input {
    appearance: none;
    width: 40px;
    height: 24px;
    border-radius: 999px;
    background: var(--line);
    position: relative;
    margin: 2px 0 0;
    cursor: pointer;
    flex: none;
  }
  .switch input::after {
    content: "";
    position: absolute;
    top: 3px;
    left: 3px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--muted);
    transition: left 0.12s;
  }
  .switch input:checked {
    background: var(--accent);
  }
  .switch input:checked::after {
    left: 19px;
    background: var(--accent-ink);
  }
  .switch input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .actions {
    justify-content: flex-end;
  }
</style>
