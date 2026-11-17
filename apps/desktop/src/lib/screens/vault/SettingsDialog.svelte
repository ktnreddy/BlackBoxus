<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import PasswordField from "../../components/PasswordField.svelte";
  import {
    browserStatus,
    createRecoveryKey,
    forgetBrowser,
    setBrowserIntegration,
    type BrowserStatus,
    errorMessage,
    helloDisable,
    helloEnable,
    recoveryKeyStatus,
    removeRecoveryKey,
    setSettings,
    showEmergencyKit,
    signOut,
    type AppStatus,
    type EmergencyKit,
  } from "../../api";

  let {
    status,
    offline,
    autoLock,
    onautolock,
    onkit,
    onchange,
    onclose,
    onnotice,
  }: {
    status: AppStatus;
    offline: boolean;
    autoLock: number;
    onautolock: (minutes: number) => void;
    onkit: (kit: EmergencyKit) => void;
    onchange: (s: AppStatus) => void;
    onclose: () => void;
    onnotice: (text: string) => void;
  } = $props();

  const CHOICES = [1, 5, 10, 15, 30, 60];

  let busy = $state(false);
  let error = $state("");
  let askingPassword = $state(false);
  let password = $state("");
  let confirmSignOut = $state(false);

  let browser = $state<BrowserStatus | null>(null);
  browserStatus().then(
    (b) => (browser = b),
    () => {},
  );

  async function toggleBrowser() {
    if (!browser) return;
    busy = true;
    error = "";
    try {
      browser = await setBrowserIntegration(!browser.enabled);
      onnotice(browser.enabled ? "Browser extension turned on." : "Browser extension turned off.");
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function removeBrowser(id: string) {
    error = "";
    try {
      browser = await forgetBrowser(id);
    } catch (e) {
      error = errorMessage(e);
    }
  }

  /** Whether the account has a recovery key; null until known or offline. */
  let hasRecovery = $state<boolean | null>(null);
  /** Which recovery change is waiting for the master password. */
  let recoveryAction = $state<"create" | "remove" | null>(null);
  let recoveryPassword = $state("");

  $effect(() => {
    if (offline) return;
    recoveryKeyStatus().then(
      (set) => (hasRecovery = set),
      () => (hasRecovery = null),
    );
  });

  async function changeRecovery(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !recoveryPassword || !recoveryAction) return;
    busy = true;
    error = "";
    const typed = recoveryPassword;
    recoveryPassword = "";
    try {
      if (recoveryAction === "create") {
        onkit(await createRecoveryKey(typed));
      } else {
        await removeRecoveryKey(typed);
        hasRecovery = false;
        recoveryAction = null;
        onnotice("Recovery key removed.");
      }
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function toggleHello() {
    busy = true;
    error = "";
    try {
      const next = status.hello.enabled ? await helloDisable() : await helloEnable();
      onchange(next);
      onnotice(next.hello.enabled ? "Windows Hello unlock is on." : "Windows Hello unlock is off.");
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function chooseAutoLock(minutes: number) {
    error = "";
    try {
      const saved = await setSettings({ auto_lock_minutes: minutes });
      onautolock(saved.auto_lock_minutes);
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function openKit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !password) return;
    busy = true;
    error = "";
    const typed = password;
    password = "";
    try {
      onkit(await showEmergencyKit(typed));
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function doSignOut() {
    if (!confirmSignOut) {
      confirmSignOut = true;
      return;
    }
    busy = true;
    error = "";
    try {
      onchange(await signOut());
    } catch (e) {
      error = errorMessage(e);
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
          disabled={busy || offline || (!status.hello.available && !status.hello.enabled)}
          onchange={toggleHello}
        />
      </label>
    </div>

    <div class="setting column">
      <div class="text">
        <span class="name"><Icon name="lock" size={18} />Lock after</span>
        <span class="small">Your vaults lock when you haven't used BlackBoxus for this long.</span>
      </div>
      <div class="seg" role="group" aria-label="Lock after">
        {#each CHOICES as minutes (minutes)}
          <button
            type="button"
            aria-pressed={autoLock === minutes}
            onclick={() => chooseAutoLock(minutes)}
            >{minutes === 60 ? "1 hour" : `${minutes} min`}</button
          >
        {/each}
      </div>
    </div>

    <div class="setting column">
      <div class="text">
        <span class="name"><Icon name="key" size={18} />Emergency Kit</span>
        <span class="small">
          See your Secret Key again, to print a new kit. Enter your master password first.
        </span>
      </div>
      {#if askingPassword}
        <form class="kit-form" onsubmit={openKit}>
          <PasswordField id="kit-password" label="Master password" bind:value={password} disabled={busy} />
          <button type="submit" class="btn ghost" disabled={busy || !password}>
            {busy ? "Checking…" : "Show kit"}
          </button>
        </form>
      {:else}
        <button type="button" class="btn ghost sm start" onclick={() => (askingPassword = true)}>
          Show Emergency Kit
        </button>
      {/if}
    </div>

    <div class="setting">
      <div class="text">
        <span class="name"><Icon name="globe" size={18} />Browser extension</span>
        <span class="small">
          Lets the BlackBoxus extension in Chrome, Edge or Brave fill logins on this computer. It
          asks this app for one login at a time, only when you click fill, and only while your
          vaults are unlocked. Turning it off disconnects every browser.
        </span>
        {#if browser?.enabled && browser.pairings.length > 0}
          <ul class="browsers">
            {#each browser.pairings as p (p.id)}
              <li>
                <span>{p.browser}</span>
                <span class="small"
                  >since {new Date(p.created_ms).toLocaleDateString(undefined, {
                    day: "numeric",
                    month: "short",
                    year: "numeric",
                  })}</span
                >
                <button type="button" class="btn ghost sm" onclick={() => removeBrowser(p.id)}>
                  Remove
                </button>
              </li>
            {/each}
          </ul>
        {:else if browser?.enabled}
          <span class="small">No browsers yet. Click the BlackBoxus button in your browser to pair.</span>
        {/if}
      </div>
      <label class="switch">
        <span class="visually-hidden">Browser extension</span>
        <input
          type="checkbox"
          role="switch"
          checked={browser?.enabled ?? false}
          disabled={busy || browser === null}
          onchange={toggleBrowser}
        />
      </label>
    </div>

    <div class="setting column">
      <div class="text">
        <span class="name"><Icon name="shield" size={18} />Recovery key</span>
        <span class="small">
          {#if offline}
            Connect to the internet to manage your recovery key.
          {:else if hasRecovery === null}
            Checking…
          {:else if hasRecovery}
            You have a recovery key. If you forget your master password, it lets you choose a new
            one. Make a new key if you think someone else has seen yours.
          {:else}
            You don't have a recovery key. Without one, a forgotten master password means your
            vaults are lost for good. Anyone with the key and your email address can open your
            account, so keep it offline with your Emergency Kit.
          {/if}
        </span>
      </div>
      {#if recoveryAction}
        <form class="kit-form" onsubmit={changeRecovery}>
          <PasswordField
            id="recovery-password"
            label="Master password"
            bind:value={recoveryPassword}
            disabled={busy}
          />
          <button
            type="submit"
            class="btn"
            class:ghost={recoveryAction === "create"}
            class:danger={recoveryAction === "remove"}
            disabled={busy || !recoveryPassword}
          >
            {#if busy}Checking…{:else if recoveryAction === "create"}Make key{:else}Remove key{/if}
          </button>
        </form>
      {:else if !offline && hasRecovery !== null}
        <div class="row">
          <button type="button" class="btn ghost sm" onclick={() => (recoveryAction = "create")}>
            {hasRecovery ? "Make a new recovery key" : "Make a recovery key"}
          </button>
          {#if hasRecovery}
            <button type="button" class="btn ghost sm" onclick={() => (recoveryAction = "remove")}>
              Remove
            </button>
          {/if}
        </div>
      {/if}
    </div>

    <div class="setting column">
      <div class="text">
        <span class="name"><Icon name="arrowLeft" size={18} />Sign out of this computer</span>
        <span class="small">
          Removes your account, Secret Key and vault copies from this computer. Your vaults stay safe
          on the server; sign in again with your Emergency Kit.
        </span>
      </div>
      <button
        type="button"
        class="btn sm start"
        class:ghost={!confirmSignOut}
        class:danger={confirmSignOut}
        disabled={busy}
        onclick={doSignOut}
      >
        {confirmSignOut ? "Sign out and remove everything here?" : "Sign out"}
      </button>
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
    width: min(600px, calc(100vw - 48px));
    max-height: calc(100vh - 48px);
    overflow-y: auto;
    padding: 28px 34px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    box-shadow: 0 50px 120px -40px rgba(0, 0, 0, 0.9);
  }
  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
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
    padding: 16px 0;
    border-top: 1px solid var(--hair);
  }
  .setting.column {
    flex-direction: column;
    gap: 12px;
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
  .start {
    align-self: flex-start;
  }
  .kit-form {
    display: flex;
    align-items: flex-end;
    gap: 12px;
    width: 100%;
  }
  .kit-form > :global(div) {
    flex: 1;
  }
  .seg {
    display: inline-flex;
    padding: 4px;
    border-radius: 999px;
    background: #111113;
    border: 1px solid var(--line);
    gap: 2px;
    flex-wrap: wrap;
  }
  .seg button {
    height: 32px;
    padding: 0 14px;
    border: 0;
    border-radius: 999px;
    background: transparent;
    color: var(--muted);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }
  .seg button[aria-pressed="true"] {
    background: var(--text);
    color: #111113;
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
  .browsers {
    list-style: none;
    margin: 6px 0 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .browsers li {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 14px;
  }
  .browsers li button {
    margin-left: auto;
  }
  .danger {
    background: #3a1414;
    border: 1px solid #6b2a2a;
    color: #ffc9c9;
  }
  .actions {
    justify-content: flex-end;
    margin-top: 8px;
  }
</style>
