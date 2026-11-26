<script lang="ts">
  import Icon from "./Icon.svelte";
  import Page from "./Page.svelte";
  import Sheet from "./Sheet.svelte";
  import NewPassword from "./NewPassword.svelte";
  import PasswordInput from "./PasswordInput.svelte";
  import TrustedPage from "./TrustedPage.svelte";
  import ImportPage from "./ImportPage.svelte";
  import ExportPage from "./ExportPage.svelte";
  import { back, opened } from "./nav";
  import type { IconName } from "./icons";
  import {
    autofillSettings,
    autofillStatus,
    type AutofillStatus,
    changePassword,
    copyText,
    emergencyStatus,
    createRecoveryKey,
    errorMessage,
    helloDisable,
    helloEnable,
    isAppError,
    mySharingId,
    recoveryKeyStatus,
    removeRecoveryKey,
    setSettings,
    showEmergencyKit,
    signOut,
    type AppStatus,
    type EmergencyKit,
    type VaultSummary,
  } from "../lib/api";
  import { unlockWords } from "../lib/unlockWords";

  let {
    status,
    autoLockMinutes,
    onautolock,
    onchange,
    onkit,
    onnotice,
    vaults,
    offline,
    syncedAt,
    syncing,
    onsync,
  }: {
    status: AppStatus;
    autoLockMinutes: number;
    onautolock: (minutes: number) => void;
    onchange: (s: AppStatus, why?: string) => void;
    onkit: (kit: EmergencyKit) => void;
    onnotice: (text: string) => void;
    vaults: VaultSummary[];
    offline: boolean;
    syncedAt: number | null;
    syncing: boolean;
    onsync: () => void;
  } = $props();

  const w = $derived(unlockWords(status));
  const CHOICES = [0, 1, 5, 15, 60];
  const lockLabel = (m: number) =>
    m === 0 ? "Straight away" : m === 60 ? "After 1 hour" : `After ${m} minute${m === 1 ? "" : "s"}`;
  const lockShort = (m: number) =>
    m === 0
      ? "Straight away"
      : m === 60
        ? "1 hour in background"
        : `${m} minute${m === 1 ? "" : "s"} in background`;

  // What the rows show on the right: recovery key and trusted contact.
  let recoveryOn = $state<boolean | null>(null);
  let contactSet = $state<boolean | null>(null);
  $effect(() => {
    if (offline || sub !== null) return;
    recoveryKeyStatus().then(
      (v) => (recoveryOn = v),
      () => {},
    );
    emergencyStatus().then(
      (v) => (contactSet = v.contact !== null),
      () => {},
    );
  });
  const synced = $derived.by(() => {
    if (offline) return "Offline · changes sync later";
    if (syncedAt === null) return "Syncing…";
    const minutes = Math.floor((Date.now() - syncedAt) / 60_000);
    return minutes < 1 ? "Synced just now" : `Synced ${minutes} min ago`;
  });

  // Filling in other apps (Android's autofill service). Checked again when
  // the person comes back from the phone's settings.
  let autofillInfo = $state<AutofillStatus | null>(null);
  const autofill = $derived(autofillInfo === null ? null : autofillInfo.enabled);
  const checkAutofill = () =>
    autofillStatus().then(
      (v) => (autofillInfo = v),
      () => {},
    );

  /** Browsers' and apps' package names, as people know them. */
  const APP_NAMES: Record<string, string> = {
    "com.android.chrome": "Chrome",
    "com.sec.android.app.sbrowser": "Samsung Internet",
    "org.mozilla.firefox": "Firefox",
    "com.brave.browser": "Brave",
    "com.microsoft.emmx": "Edge",
    "com.duckduckgo.mobile.android": "DuckDuckGo",
  };
  function ago(ms: number): string {
    const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return new Date(ms).toLocaleDateString();
  }
  /** What happened the last time, in plain words, so the person (and we)
   *  can tell why "Fill with BlackBoxus" did or didn't appear. */
  const autofillLast = $derived.by(() => {
    const last = autofillInfo?.last;
    if (!autofillInfo?.enabled || !last) return "";
    if (last.at === 0) {
      return last.connected_at === 0
        ? "Android hasn't started BlackBoxus's autofill yet. Restart the phone, then tap a password field in any app."
        : "Android hasn't asked about any form yet. Tap a username or password field in another app.";
    }
    const app = APP_NAMES[last.app] ?? last.app;
    const when = ago(last.at);
    switch (last.outcome) {
      case "offered":
        return `Last: ${app}, ${when}. “Fill with BlackBoxus” was offered.`;
      case "no_fields":
        return `Last: ${app}, ${when}. No username or password field was found there, so nothing was offered.`;
      case "error":
        return `Last: ${app}, ${when}. Something went wrong reading that form, so nothing was offered.`;
      default:
        return `Last: ${app}, ${when}.`;
    }
  });
  checkAutofill();
  $effect(() => {
    const again = () => {
      if (document.visibilityState === "visible") checkAutofill();
    };
    document.addEventListener("visibilitychange", again);
    return () => document.removeEventListener("visibilitychange", again);
  });

  type Sub = "password" | "recovery" | "kit" | "trusted" | "import" | "export";
  let sub = $state<Sub | null>(null);
  let lockSheet = $state(false);
  let signOutSheet = $state(false);

  function open(next: Sub) {
    error = "";
    sub = next;
    opened(() => {
      sub = null;
      error = "";
    });
  }

  let busy = $state(false);
  let error = $state("");

  let sharingId = $state("");
  mySharingId().then(
    (id) => (sharingId = id),
    () => {},
  );

  async function copySharingId() {
    try {
      await copyText(sharingId);
      onnotice("Sharing ID copied. Send it to people who want to share a vault with you.");
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  /** Turning it on asks for a fingerprint; turning it off deletes the
   *  key kept for it. The switch only moves once that has happened. */
  async function toggleFingerprint(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    input.checked = status.hello.enabled;
    if (busy) return;
    busy = true;
    try {
      const next = status.hello.enabled ? await helloDisable() : await helloEnable();
      onchange(next);
      onnotice(`${w.Unlock} is ${next.hello.enabled ? "on" : "off"}.`);
    } catch (e) {
      if (!(isAppError(e) && e.code === "hello_cancelled")) onnotice(errorMessage(e));
    } finally {
      busy = false;
      input.checked = status.hello.enabled;
    }
  }

  async function chooseLock(minutes: number) {
    try {
      const saved = await setSettings({ auto_lock_minutes: minutes });
      onautolock(saved.auto_lock_minutes);
    } catch (e) {
      onnotice(errorMessage(e));
    }
    back();
  }

  // Change master password
  let current = $state("");
  let next = $state("");
  let again = $state("");
  let nextOk = $state(false);

  async function submitChange(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !current || !nextOk) return;
    busy = true;
    error = "";
    const [c, n, a] = [current, next, again];
    current = "";
    try {
      await changePassword(c, n, a);
      next = "";
      again = "";
      back();
      onnotice("Master password changed. Your other devices need the new one to sign in.");
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  // Recovery key
  let hasRecovery = $state<boolean | null>(null);
  $effect(() => {
    if (sub !== "recovery" || offline) return;
    recoveryKeyStatus().then(
      (set) => (hasRecovery = set),
      () => (hasRecovery = null),
    );
  });
  let recoveryPassword = $state("");

  async function makeRecoveryKey(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !recoveryPassword) return;
    busy = true;
    error = "";
    const typed = recoveryPassword;
    recoveryPassword = "";
    try {
      const kit = await createRecoveryKey(typed);
      back();
      onkit(kit);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function dropRecoveryKey() {
    if (busy || !recoveryPassword) return;
    busy = true;
    error = "";
    const typed = recoveryPassword;
    recoveryPassword = "";
    try {
      await removeRecoveryKey(typed);
      hasRecovery = false;
      onnotice("Recovery key removed.");
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  // Emergency Kit
  let kitPassword = $state("");
  async function openKit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !kitPassword) return;
    busy = true;
    error = "";
    const typed = kitPassword;
    kitPassword = "";
    try {
      const kit = await showEmergencyKit(typed);
      back();
      onkit(kit);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function doSignOut() {
    busy = true;
    try {
      onchange(await signOut());
    } catch (e) {
      onnotice(errorMessage(e));
      busy = false;
    }
  }

  function openLock() {
    lockSheet = true;
    opened(() => (lockSheet = false));
  }
</script>

<header class="st-head"><h1 class="st-h1">Settings</h1></header>
<div class="st-main m-scroll">
  <div class="st-account">
    <span class="st-avatar">{status.account?.email[0]?.toUpperCase() ?? "?"}</span>
    <div class="st-who">
      <span class="st-email">{status.account?.email}</span>
      <span class="st-sub">{syncing ? "Syncing…" : synced}</span>
    </div>
    <button type="button" class="st-syncnow" onclick={onsync} disabled={syncing}>
      {syncing ? "Syncing…" : "Sync now"}
    </button>
  </div>

  <p class="st-section">Unlocking</p>
  <div class="st-group">
    {#if status.hello.available || status.hello.setup_needed}
      <label class="st-toggle">
        <span class="st-text">
          <span class="st-label">Unlock with {w.name}</span>
          <span class="st-sub">
            {#if !status.hello.available}
              Set up {w.name} in {w.where} first
            {:else if offline && !status.hello.enabled}
              Needs a connection to turn on
            {:else if status.hello.enabled}
              Master password still needed every 14 days
            {:else}
              Uses the {w.things} saved on this {w.device}
            {/if}
          </span>
        </span>
        <input
          class="m-switch"
          type="checkbox"
          role="switch"
          checked={status.hello.enabled}
          disabled={busy || !status.hello.available || (offline && !status.hello.enabled)}
          onchange={toggleFingerprint}
        />
      </label>
    {/if}
    <button type="button" class="st-row end" onclick={openLock}>
      <span class="st-text"><span class="st-label">Lock after: {lockShort(autoLockMinutes)}</span><span class="st-sub">How long BlackBoxus stays open while you're away. Locking erases the keys from memory.</span></span>
      <Icon name="next" size={18} />
    </button>
  </div>

  {#if status.hello.available || status.hello.setup_needed}
    <p class="st-note">
      {#if status.hello.kind === "face_id"}
        Face ID is set up in {w.where}. If it's reset or another appearance is added, Face ID unlock
        turns off until you turn it on again here.
      {:else}
        {w.things.charAt(0).toUpperCase() + w.things.slice(1)} are added and removed in {w.where}. Any of
        them can unlock BlackBoxus. When one is added, {w.unlock} turns off until you turn it on again
        here.
      {/if}
    </p>
  {/if}

  {#if autofill !== null}
    <p class="st-section">Autofill</p>
    <div class="st-group">
      <button type="button" class="st-row end" onclick={() => autofillSettings()}>
        <span class="st-text">
          <span class="st-label">Fill in other apps</span>
          <span class="st-sub">
            {autofill ? "BlackBoxus is your autofill service" : "Choose BlackBoxus as your autofill service"}
          </span>
        </span>
        <span class="st-value">{autofill ? "On" : "Off"}</span>
        <Icon name="next" size={18} />
      </button>
      {#if autofill && autofillInfo?.chrome != null}
        <button type="button" class="st-row end" onclick={() => autofillSettings(true)}>
          <span class="st-text">
            <span class="st-label">Fill in Chrome</span>
            <span class="st-sub">
              {autofillInfo.chrome
                ? "Chrome lets BlackBoxus fill its pages"
                : "Chrome uses its own password manager. Tap, choose “Autofill using another service”, then restart Chrome"}
            </span>
          </span>
          <span class="st-value">{autofillInfo.chrome ? "On" : "Off"}</span>
          <Icon name="next" size={18} />
        </button>
      {/if}
    </div>
    <p class="st-note">
      Tap a username or password field in any app, then choose “Fill with BlackBoxus”. If a browser offers
      its own password manager instead, turn that off in the browser's settings.
    </p>
    {#if autofillLast}<p class="st-note">{autofillLast}</p>{/if}
  {/if}

  <p class="st-section">Security</p>
  <div class="st-group">
    <button type="button" class="st-row" onclick={() => open("password")} disabled={offline}>
      <span class="st-text"><span class="st-label">Change master password</span><span class="st-sub">The password you type to unlock. Your other devices ask for the new one next time.</span></span>{#if offline}<span class="st-value">Needs a connection</span>{/if}
      <Icon name="next" size={18} />
    </button>
    <button type="button" class="st-row" onclick={() => open("recovery")} disabled={offline}>
      <span class="st-text"><span class="st-label">Recovery key</span><span class="st-sub">A spare key for choosing a new master password if you forget yours.</span></span>{#if recoveryOn !== null}<span class="st-value">{recoveryOn ? "On" : "Off"}</span>{/if}
      <Icon name="next" size={18} />
    </button>
    <button type="button" class="st-row" onclick={() => open("trusted")} disabled={offline}>
      <span class="st-text"><span class="st-label">Trusted contact</span><span class="st-sub">Someone who can ask to read your vaults if you can't. You get a waiting period to say no.</span></span>{#if contactSet !== null}<span class="st-value">{contactSet ? "Set" : "Not set"}</span>{/if}
      <Icon name="next" size={18} />
    </button>
    <button type="button" class="st-row" onclick={() => open("kit")}>
      <span class="st-text"><span class="st-label">Emergency Kit</span><span class="st-sub">Your email and Secret Key, needed to sign in on a new device. Keep it on paper.</span></span><span class="st-value">View</span>
      <Icon name="next" size={18} />
    </button>
  </div>

  <p class="st-section">Data</p>
  <div class="st-group">
    <button type="button" class="st-row" onclick={() => open("import")} disabled={offline}>
      <span class="st-text"><span class="st-label">Import passwords</span><span class="st-sub">From Chrome, another password manager (CSV), or a BlackBoxus export.</span></span>
      <Icon name="next" size={18} />
    </button>
    <button type="button" class="st-row" onclick={() => open("export")}>
      <span class="st-text"><span class="st-label">Export your vaults</span><span class="st-sub">An encrypted backup file, or a CSV to move to another app.</span></span>
      <Icon name="next" size={18} />
    </button>
    {#if sharingId}
      <button type="button" class="st-row" onclick={copySharingId}>
        <span class="st-text"><span class="st-label">Your sharing ID</span><span class="st-sub">Give this to someone so they can share a vault with you. Tap to copy.</span></span><span class="st-value st-mono">{sharingId.slice(0, 8)}…</span>
      </button>
    {/if}
    <button
      type="button"
      class="st-row end danger"
      onclick={() => {
        signOutSheet = true;
        opened(() => (signOutSheet = false));
      }}
    >
      <span class="st-text"><span class="st-label">Sign out of this phone</span><span class="st-sub">Your vaults stay safe on the server. Signing in again needs your email, Secret Key and master password.</span></span>
    </button>
  </div>

  <p class="st-version">BlackBoxus {status.version}</p>
</div>

{#if lockSheet}
  <Sheet label="Lock after" gap={4}>
    <h2 class="sheet-title">Lock after</h2>
    <p class="sx-sheet-lede">How long BlackBoxus stays open after you leave the app.</p>
    <div role="radiogroup" aria-label="Lock after">
      {#each CHOICES as m (m)}
        <button type="button" role="radio" aria-checked={autoLockMinutes === m} class="choice" onclick={() => chooseLock(m)}>
          <span class="radio" aria-hidden="true"></span>
          <span class="st-grow">{lockLabel(m)}</span>
          {#if m === 1}<span class="sx-rec">Recommended</span>{/if}
        </button>
      {/each}
    </div>
  </Sheet>
{/if}

{#if signOutSheet}
  <Sheet label="Sign out">
    <h2 class="sheet-title">Sign out of this phone?</h2>
    <p class="sx-sheet-lede">
      Your vaults stay safe on the server. To sign in again you'll need your email, Secret Key and
      master password.
    </p>
    <button type="button" class="m-btn danger" onclick={doSignOut} disabled={busy}>Sign out</button>
    <button type="button" class="m-btn ghost" onclick={back} disabled={busy}>Cancel</button>
  </Sheet>
{/if}

{#if sub === "password"}
  <Page title="Change master password" backLabel="Settings" form tight>
    <p class="m-lede">Your other devices will ask for the new one next time they unlock.</p>
    <form id="pw-form" class="sx-form" onsubmit={submitChange}>
      <PasswordInput id="cp-current" label="Current password" bind:value={current} disabled={busy} />
      <NewPassword email={status.account?.email ?? ""} bind:password={next} bind:confirm={again} bind:ok={nextOk} disabled={busy} label="New password" />
      {#if error}<p class="m-error" role="alert">{error}</p>{/if}
    </form>
    {#snippet footer()}
      <p class="sx-note">Your recovery key keeps working.</p>
      <button type="submit" form="pw-form" class="m-fl-btn" disabled={busy || !current || !nextOk}>
        {busy ? "Changing…" : "Change password"}
      </button>
    {/snippet}
  </Page>
{:else if sub === "recovery"}
  <Page title="Recovery key" backLabel="Settings" form>
    <p class="m-lede">
      If you forget your master password, a recovery key lets you choose a new one. Keep it on
      paper, away from your phone.
    </p>
    {#if hasRecovery === null}
      <p class="m-small">Checking…</p>
    {:else}
      <div class="m-note" class:warn={!hasRecovery}>
        <Icon name={hasRecovery ? "check" : "alert"} size={22} />
        <span>
          {hasRecovery
            ? "Your account has a recovery key. It was shown once, when it was made."
            : "Your account has no recovery key. Without one, a forgotten password means losing your data."}
        </span>
      </div>
      <div class="m-note">
        <Icon name="info" size={22} />
        <span>Anyone with this key can open your vaults. Screenshots are blocked while it's on screen.</span>
      </div>
      <form id="rk-form" class="sx-form" onsubmit={makeRecoveryKey}>
        <PasswordInput id="rk-password" label="Master password, to confirm" bind:value={recoveryPassword} disabled={busy} />
        {#if error}<p class="m-error" role="alert">{error}</p>{/if}
      </form>
    {/if}
    {#snippet footer()}
      {#if hasRecovery !== null}
        <button type="submit" form="rk-form" class={hasRecovery ? "sx-danger" : "m-fl-btn"} disabled={busy || !recoveryPassword}>
          {hasRecovery ? "Make a new key (old one stops working)" : "Make a recovery key"}
        </button>
        {#if hasRecovery}
          <button type="button" class="sx-quiet" disabled={busy || !recoveryPassword} onclick={dropRecoveryKey}>
            Remove recovery key
          </button>
        {/if}
      {/if}
    {/snippet}
  </Page>
{:else if sub === "kit"}
  <Page title="Emergency Kit" backLabel="Settings" form>
    <p class="m-lede">It shows your Secret Key, which you need to sign in on a new device. Enter your master password to see it.</p>
    <form id="kit-form" class="sx-form" onsubmit={openKit}>
      <PasswordInput id="kit-password" label="Master password" bind:value={kitPassword} disabled={busy} />
      {#if error}<p class="m-error" role="alert">{error}</p>{/if}
    </form>
    {#snippet footer()}
      <button type="submit" form="kit-form" class="m-fl-btn" disabled={busy || !kitPassword}>Show the kit</button>
    {/snippet}
  </Page>
{:else if sub === "trusted"}
  <TrustedPage {onnotice} />
{:else if sub === "import"}
  <ImportPage {vaults} {onnotice} />
{:else if sub === "export"}
  <ExportPage email={status.account?.email ?? ""} {onnotice} />
{/if}

<style>
  .st-head {
    padding: calc(56px + var(--sb)) 24px 8px;
  }
  .st-h1 {
    margin: 0;
    font-size: 30px;
    font-weight: 400;
    letter-spacing: -0.02em;
  }
  .st-main {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 12px 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .st-syncnow {
    margin-left: auto;
    flex: none;
    height: 36px;
    padding: 0 14px;
    border-radius: 18px;
    border: 1px solid #2a2a2e;
    background: #151517;
    color: #f4f4f5;
    font: 500 14px "DM Sans Variable", sans-serif;
  }
  .st-syncnow:disabled {
    color: #a1a1aa;
  }
  .st-account {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 14px 16px;
    border-radius: 20px;
    background: #151517;
    border: 1px solid #1f1f22;
  }
  .st-avatar {
    width: 44px;
    height: 44px;
    flex: none;
    border-radius: 22px;
    background: rgba(255, 106, 26, 0.14);
    color: #ffb27f;
    display: grid;
    place-items: center;
    font-weight: 600;
    font-size: 17px;
  }
  .st-who {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .st-email {
    font-size: 16px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .st-sub {
    font-size: 13px;
    color: #a1a1aa;
  }
  .st-note {
    margin: 0 8px;
    font-size: 13px;
    line-height: 1.45;
    color: #a1a1aa;
  }
  .st-section {
    margin: 10px 8px 0;
    font-size: 13px;
    color: #a1a1aa;
  }
  .st-group {
    border-radius: 20px;
    background: #151517;
    border: 1px solid #1f1f22;
    overflow: hidden;
    flex: none;
  }
  .st-toggle {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 64px;
    padding: 0 16px;
    border-bottom: 1px solid #1f1f22;
  }
  .st-text {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .st-label {
    font-size: 16px;
  }
  .st-row .st-text {
    min-width: 0;
    padding: 10px 0;
  }
  .st-row {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 56px;
    padding: 0 16px;
    border: 0;
    border-bottom: 1px solid #1f1f22;
    background: none;
    color: #f4f4f5;
    font: 400 16px "DM Sans Variable", sans-serif;
    text-align: left;
  }
  .st-row.end {
    border-bottom: 0;
  }
  .st-row :global(svg) {
    flex: none;
    margin-left: auto;
    color: #a1a1aa;
  }
  .st-row.danger {
    color: #fca5a5;
  }
  .st-row:disabled {
    opacity: 0.55;
  }
  .st-grow {
    /* The label keeps its width (up to 70% of the row, then it wraps);
       the value beside it gives way and ends in "…". */
    flex: 1 0 auto;
    max-width: 70%;
    padding: 8px 0;
  }
  .st-value {
    flex: 0 1 auto;
    max-width: 55%;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: #a1a1aa;
    font-size: 15px;
  }
  .st-mono {
    font-family: var(--font-mono);
    font-size: 14px;
  }
  .st-version {
    margin: 8px 0 0;
    text-align: center;
    font-size: 13px;
    color: #71717a;
  }
  .sheet-title {
    margin: 0 8px 4px;
    font-size: 20px;
    font-weight: 500;
  }
  .sx-sheet-lede {
    margin: 0 8px 10px;
    font-size: 14px;
    line-height: 1.45;
    color: #a1a1aa;
  }
  .choice .st-grow {
    overflow-wrap: anywhere;
  }
  .sx-rec {
    font-size: 13px;
    color: #a1a1aa;
  }
  .choice {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 56px;
    padding: 0 12px;
    border: 0;
    border-radius: 14px;
    background: none;
    color: #f4f4f5;
    font: 400 16px "DM Sans Variable", sans-serif;
    text-align: left;
  }
  .choice[aria-checked="true"] {
    background: rgba(255, 106, 26, 0.08);
  }
  .radio {
    box-sizing: border-box;
    width: 22px;
    height: 22px;
    border-radius: 11px;
    border: 2px solid #3f3f46;
    flex: none;
  }
  .choice[aria-checked="true"] .radio {
    border-color: #ff6a1a;
    background: radial-gradient(circle, #ff6a1a 0 5px, transparent 5.5px);
  }
  .sx-form {
    display: contents;
  }
  .sx-note {
    margin: 0;
    font-size: 13px;
    line-height: 1.45;
    color: #a1a1aa;
    text-align: center;
  }
  .sx-danger {
    width: 100%;
    min-height: 54px;
    border-radius: 27px;
    border: 1px solid rgba(252, 165, 165, 0.4);
    background: none;
    color: #fca5a5;
    font: 500 16px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .sx-danger:disabled,
  .sx-quiet:disabled {
    opacity: 0.45;
  }
  .sx-quiet {
    min-height: 44px;
    border: 0;
    background: none;
    color: #a1a1aa;
    font: 400 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
</style>
