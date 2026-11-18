<script lang="ts">
  import Icon from "./Icon.svelte";
  import Page from "./Page.svelte";
  import PasswordInput from "./PasswordInput.svelte";
  import { tint } from "./tint";
  import {
    denyEmergency,
    emergencyStatus,
    errorMessage,
    lookUpContact,
    removeTrustedContact,
    requestEmergency,
    setTrustedContact,
    type EmergencyView,
    type GrantView,
    type LookedUp,
  } from "../lib/api";

  let { onnotice }: { onnotice: (text: string) => void } = $props();

  const WAITS = [1, 3, 7, 14, 30];

  let view = $state<EmergencyView | null>(null);
  let busy = $state(false);
  let error = $state("");

  let adding = $state(false);
  let sharingId = $state("");
  let found = $state<LookedUp | null>(null);
  let matched = $state(false);
  let waitDays = $state(7);
  let password = $state("");
  let confirmRemove = $state(false);

  emergencyStatus().then(
    (v) => (view = v),
    (e: unknown) => (error = errorMessage(e)),
  );

  async function run(task: () => Promise<void>) {
    if (busy) return;
    busy = true;
    error = "";
    try {
      await task();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  function lookUp(event: SubmitEvent) {
    event.preventDefault();
    if (!sharingId.trim()) return;
    run(async () => {
      found = await lookUpContact(sharingId.trim());
      matched = false;
    });
  }

  function save(event: SubmitEvent) {
    event.preventDefault();
    const typed = password;
    password = "";
    if (!found || !matched || !typed) return;
    const id = found.sharing_id;
    run(async () => {
      view = await setTrustedContact(id, waitDays, typed);
      adding = false;
      sharingId = "";
      found = null;
      matched = false;
      onnotice("Trusted contact saved.");
    });
  }

  const days = (n: number) => (n === 1 ? "1 day" : `${n} days`);
  const when = (ms: number | null) =>
    ms === null ? "" : new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  /** Time until access opens, such as "5 days, 14 hours". */
  const left = (ms: number | null) => {
    if (ms === null) return "";
    const hours = Math.max(0, Math.ceil((ms - Date.now()) / 3_600_000));
    const d = Math.floor(hours / 24);
    const h = hours % 24;
    const part = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
    if (d === 0) return part(h, "hour");
    return h === 0 ? part(d, "day") : `${part(d, "day")}, ${part(h, "hour")}`;
  };
  const progress = (g: GrantView) => {
    if (g.release_at_ms === null) return 0;
    const total = g.wait_days * 86_400_000;
    const left = Math.max(0, g.release_at_ms - Date.now());
    return Math.round(((total - left) / total) * 100);
  };
</script>

<Page title="Trusted contact" backLabel="Settings">
  <p class="m-lede">
    Someone who can ask for access if you lose your password or can't be reached. You get time to
    say no.
  </p>

  {#if error}<p class="m-error" role="alert">{error}</p>{/if}

  {#if view}
    {#if view.contact}
      {@const c = view.contact}
      <div class="tc-card">
        <div class="tc-who">
          <span class="tc-avatar">{c.sharing_id.split("-")[1]?.[0]?.toUpperCase() ?? "?"}</span>
          <span class="tc-text">
            <span class="tc-name">{c.sharing_id}</span>
            <span class="tc-sub">Your trusted contact</span>
          </span>
        </div>
        <div class="tc-wait">
          <span class="tc-wait-label">Waiting period</span>
          <span class="tc-wait-value">{days(c.wait_days)}</span>
        </div>
      </div>
      {#if c.stage === "requested"}
        <div class="tc-request">
          <span class="tc-name">They asked for access</span>
          <span class="tc-body">If you do nothing, they can read your vaults in <strong class="tc-when">{left(c.release_at_ms)}</strong>.</span>
          <div class="tc-bar" aria-hidden="true"><svg width="100%" height="6" preserveAspectRatio="none" viewBox="0 0 100 6"><rect width={progress(c)} height="6" fill="#ff6a1a" /></svg></div>
          <div class="tc-actions">
            <button type="button" class="tc-deny" onclick={() => run(async () => {
              view = await denyEmergency(c.sharing_id);
              onnotice("Request denied.");
            })} disabled={busy}>Deny</button>
          </div>
        </div>
      {:else if c.stage === "released"}
        <div class="m-note warn"><Icon name="alert" size={22} /><span>They can read your vaults now. Remove them to stop that.</span></div>
      {/if}
      <button
        type="button"
        class="tc-remove"
        disabled={busy}
        onclick={() => {
          if (!confirmRemove) {
            confirmRemove = true;
            return;
          }
          run(async () => {
            view = await removeTrustedContact();
            confirmRemove = false;
            onnotice("Trusted contact removed.");
          });
        }}
        onblur={() => (confirmRemove = false)}
      >
        {confirmRemove ? "Tap again to remove" : "Remove trusted contact"}
      </button>
    {:else if !adding}
      <div class="m-note"><Icon name="info" size={22} /><span>You haven't named a trusted contact.</span></div>
      <button type="button" class="m-btn" onclick={() => (adding = true)}>Name a trusted contact</button>
    {:else if !found}
      <form class="form" onsubmit={lookUp}>
        <div>
          <label class="m-label" for="tc-id">Their sharing ID</label>
          <div class="m-field">
            <input id="tc-id" class="mono" bind:value={sharingId} autocapitalize="off" spellcheck="false" disabled={busy} />
          </div>
          <p class="m-small hint">They'll find it in their BlackBoxus Settings.</p>
        </div>
        <button type="submit" class="m-btn" disabled={busy || !sharingId.trim()}>Look up</button>
      </form>
    {:else}
      <form class="form" onsubmit={save}>
        <div class="number">
          <span class="main">Check the safety number with them</span>
          <span class="digits mono">{found.safety_number.join(" ")}</span>
          <span class="m-small">Compare it in person or on a call. If it matches, nobody slipped in their own key.</span>
          <div class="pair">
            <button type="button" class="m-btn ghost" onclick={() => {
              found = null;
              sharingId = "";
            }}>Doesn't match</button>
            <button type="button" class="m-btn" class:off={!matched} aria-pressed={matched} onclick={() => (matched = true)}>
              {matched ? "Matched" : "It matches"}
            </button>
          </div>
        </div>
        <div>
          <span class="m-label">Waiting period</span>
          <div class="waits" role="radiogroup" aria-label="Waiting period">
            {#each WAITS as d (d)}
              <button type="button" role="radio" aria-checked={waitDays === d} class="wait" onclick={() => (waitDays = d)}>
                {days(d)}
              </button>
            {/each}
          </div>
        </div>
        <PasswordInput id="tc-password" label="Master password, to confirm" bind:value={password} disabled={busy} />
        <button type="submit" class="m-btn" disabled={busy || !matched || !password}>Save trusted contact</button>
      </form>
    {/if}

    {#if view.received.length > 0}
      <p class="m-section">People who trust you</p>
      <div class="m-list">
        {#each view.received as g (g.sharing_id)}
          <div class="m-row">
            <span class="grow">
              <span class="main mono">{g.sharing_id}</span>
              <span class="sub">
                {g.stage === "idle"
                  ? `You can ask for access. They have ${days(g.wait_days)} to say no.`
                  : g.stage === "requested"
                    ? `Asked. Opens ${when(g.release_at_ms)}.`
                    : "Open it on your computer."}
              </span>
            </span>
            {#if g.stage === "idle"}
              <button type="button" class="m-btn ghost small" disabled={busy} onclick={() => run(async () => {
                view = await requestEmergency(g.sharing_id);
              })}>Ask</button>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  {:else if !error}
    <p class="m-small">Loading…</p>
  {/if}
</Page>

<style>
  .tc-card {
    padding: 16px;
    border-radius: 20px;
    background: #151517;
    border: 1px solid #1f1f22;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .tc-who {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .tc-avatar {
    width: 44px;
    height: 44px;
    flex: none;
    border-radius: 22px;
    background: #1c1c1f;
    display: grid;
    place-items: center;
    color: #93c5fd;
    font-weight: 600;
  }
  .tc-text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .tc-name {
    font-size: 16px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .tc-sub {
    font-size: 13px;
    color: #a1a1aa;
  }
  .tc-wait {
    box-sizing: border-box;
    border-top: 1px solid #1f1f22;
    display: flex;
    justify-content: space-between;
    align-items: center;
    min-height: 48px;
    padding: 0 4px;
  }
  .tc-wait-label {
    font-size: 15px;
    color: #d4d4d8;
  }
  .tc-wait-value {
    font-size: 16px;
    font-weight: 500;
  }
  .tc-request {
    padding: 18px;
    border-radius: 20px;
    background: rgba(255, 106, 26, 0.1);
    border: 1px solid rgba(255, 106, 26, 0.38);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .tc-body {
    font-size: 14px;
    line-height: 1.5;
    color: #d4d4d8;
  }
  .tc-when {
    color: #ffb27f;
    font-weight: 600;
  }
  .tc-bar {
    height: 6px;
    border-radius: 3px;
    background: #2a2a2e;
    overflow: hidden;
  }
  .tc-bar svg {
    display: block;
  }
  .tc-actions {
    display: grid;
    gap: 10px;
    margin-top: 4px;
  }
  .tc-deny {
    min-height: 48px;
    border-radius: 24px;
    border: 0;
    background: #ff6a1a;
    color: #140800;
    font: 600 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .tc-remove {
    min-height: 50px;
    flex: none;
    border-radius: 25px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #fca5a5;
    font: 500 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .mono {
    font-family: var(--font-mono);
  }
  .number {
    padding: 18px;
    border-radius: 20px;
    background: rgba(255, 106, 26, 0.1);
    border: 1px solid var(--accent-line);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .number {
    background: var(--panel);
  }
  .main {
    font-weight: 500;
  }
  .digits {
    font-size: 20px;
    letter-spacing: 1px;
    color: var(--accent-soft);
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .hint {
    margin: 8px 4px 0;
  }
  .pair {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  .pair .m-btn {
    min-height: 48px;
    font-size: 15px;
  }
  .waits {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .wait {
    min-height: 44px;
    padding: 0 16px;
    border-radius: 22px;
    border: 1px solid var(--line);
    background: none;
    color: var(--soft);
  }
  .wait[aria-checked="true"] {
    border-color: var(--accent-line);
    background: rgba(255, 106, 26, 0.16);
    color: var(--text);
  }
</style>
