<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import PasswordField from "../../components/PasswordField.svelte";
  import {
    denyEmergency,
    emergencyStatus,
    errorMessage,
    lookUpContact,
    openEmergency,
    removeTrustedContact,
    requestEmergency,
    setTrustedContact,
    type EmergencyView,
    type GrantView,
    type LookedUp,
    type VaultSummary,
  } from "../../api";

  let {
    onclose,
    onopen,
    onnotice,
  }: {
    onclose: () => void;
    /** An account opened as its trusted contact, with its vaults. */
    onopen: (owner: string, vaults: VaultSummary[]) => void;
    onnotice: (text: string) => void;
  } = $props();

  const WAITS = [1, 3, 7, 14, 30];

  let view = $state<EmergencyView | null>(null);
  let busy = $state(false);
  let error = $state("");

  // Naming a contact: sharing ID, then the safety number, then the
  // master password.
  let adding = $state(false);
  let sharingId = $state("");
  let found = $state<LookedUp | null>(null);
  let matched = $state(false);
  let waitDays = $state(7);
  let password = $state("");
  let confirmRemove = $state(false);

  emergencyStatus().then(
    (v) => (view = v),
    (e) => (error = errorMessage(e)),
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
      cancelAdding();
      onnotice("Trusted contact saved.");
    });
  }

  function cancelAdding() {
    adding = false;
    sharingId = "";
    found = null;
    matched = false;
    password = "";
  }

  function remove() {
    run(async () => {
      view = await removeTrustedContact();
      confirmRemove = false;
      onnotice("Trusted contact removed.");
    });
  }

  function deny(contact: GrantView) {
    run(async () => {
      view = await denyEmergency(contact.sharing_id);
      onnotice("Request denied.");
    });
  }

  function request(grant: GrantView) {
    run(async () => {
      view = await requestEmergency(grant.sharing_id);
    });
  }

  function open(grant: GrantView) {
    run(async () => {
      onopen(grant.sharing_id, await openEmergency(grant.sharing_id));
    });
  }

  function when(ms: number | null): string {
    if (ms === null) return "";
    return new Date(ms).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  }

  function days(n: number): string {
    return n === 1 ? "1 day" : `${n} days`;
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Escape" && !busy) onclose();
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop" role="presentation">
  <div class="card accent dialog" role="dialog" aria-modal="true" aria-labelledby="trusted-title">
    <div class="top">
      <h1 id="trusted-title" class="title">Trusted contacts</h1>
      <button type="button" class="icon-btn" aria-label="Close" onclick={onclose} disabled={busy}>
        <Icon name="x" />
      </button>
    </div>

    {#if error}
      <p class="note" role="alert"><Icon name="alert" />{error}</p>
    {/if}

    {#if !view}
      <p class="small">{error ? "" : "Loading…"}</p>
    {:else}
      <section class="part">
        <h2 class="h2">Your trusted contact</h2>
        <p class="small">
          Someone who can ask to see your vaults if something happens to you. They get access only
          after a waiting period, and you can deny the request until then. Choose someone you trust
          completely: once in, they can see every password you can.
        </p>

        {#if view.contact && !adding}
          {@const c = view.contact}
          <div class="grant">
            <div class="who">
              <span class="mono selectable">{c.sharing_id}</span>
              <span class="small">Waiting period {days(c.wait_days)}</span>
            </div>
            {#if c.stage === "idle"}
              <span class="tag">No request</span>
            {:else if c.stage === "requested"}
              <span class="tag warn">Asked for access</span>
            {:else}
              <span class="tag warn">Has access</span>
            {/if}
          </div>
          {#if c.stage === "requested"}
            <div class="card alert">
              <p class="small">
                They asked to see your vaults. Access opens on {when(c.release_at_ms)} unless you deny
                it.
              </p>
              <button type="button" class="btn primary sm" disabled={busy} onclick={() => deny(c)}>
                Deny request
              </button>
            </div>
          {:else if c.stage === "released"}
            <p class="small">
              They can read your vaults. Remove them to end that access, then change any passwords
              that matter.
            </p>
          {/if}
          <div class="row">
            <button type="button" class="btn ghost sm" disabled={busy} onclick={() => (adding = true)}>
              Change contact
            </button>
            {#if confirmRemove}
              <button type="button" class="btn ghost sm danger" disabled={busy} onclick={remove}>
                Remove for sure
              </button>
              <button
                type="button"
                class="btn ghost sm"
                disabled={busy}
                onclick={() => (confirmRemove = false)}>Keep</button
              >
            {:else}
              <button
                type="button"
                class="btn ghost sm"
                disabled={busy}
                onclick={() => (confirmRemove = true)}>Remove</button
              >
            {/if}
          </div>
        {:else if !adding}
          <button type="button" class="btn ghost sm start" onclick={() => (adding = true)}>
            <Icon name="plus" size={15} />Choose a trusted contact
          </button>
        {/if}

        {#if adding}
          {#if !found}
            <form class="stack" onsubmit={lookUp}>
              <div>
                <label class="label" for="contact-id">Their sharing ID</label>
                <div class="field">
                  <!-- svelte-ignore a11y_autofocus -->
                  <input
                    id="contact-id"
                    type="text"
                    class="mono"
                    bind:value={sharingId}
                    autocomplete="off"
                    spellcheck="false"
                    placeholder="0QKX4Q-SX48Q-J7J8K-HZYQ2-D7Y27"
                    autofocus
                    disabled={busy}
                  />
                </div>
                <span class="small">They find it on their Share screen.</span>
              </div>
              <div class="row">
                <button type="button" class="btn ghost sm" disabled={busy} onclick={cancelAdding}>
                  Cancel
                </button>
                <button type="submit" class="btn primary sm" disabled={busy || !sharingId.trim()}>
                  {busy ? "Looking up…" : "Look up"}
                </button>
              </div>
            </form>
          {:else}
            <form class="stack" onsubmit={save}>
              <div class="check">
                <span class="found">
                  <Icon name="shield" size={15} />Their keys were found in the public key log
                </span>
                <p class="small">
                  Compare this safety number with them in person or on a call. It matches only if
                  nobody has swapped their keys.
                </p>
                <div class="number mono" aria-label="Safety number">
                  {#each found.safety_number as group, i (i)}<span>{group}</span>{/each}
                </div>
                <label class="match">
                  <input type="checkbox" bind:checked={matched} />
                  We compared it and it matches
                </label>
              </div>
              <div>
                <label class="label" for="wait-days">Waiting period</label>
                <div class="field">
                  <select id="wait-days" bind:value={waitDays} disabled={busy}>
                    {#each WAITS as d (d)}
                      <option value={d}>{days(d)}</option>
                    {/each}
                  </select>
                </div>
                <span class="small">
                  How long you have to deny a request. Longer is safer if you check the app rarely.
                </span>
              </div>
              <PasswordField
                id="contact-password"
                label="Your master password"
                bind:value={password}
                autocomplete="current-password"
                disabled={busy}
              />
              <div class="row">
                <button type="button" class="btn ghost sm" disabled={busy} onclick={cancelAdding}>
                  Cancel
                </button>
                <button
                  type="submit"
                  class="btn primary sm"
                  disabled={busy || !matched || !password}
                >
                  {busy ? "Saving…" : "Save trusted contact"}
                </button>
              </div>
            </form>
          {/if}
        {/if}
      </section>

      <div class="rule"></div>

      <section class="part">
        <h2 class="h2">People who trust you</h2>
        {#if view.received.length === 0}
          <p class="small">Nobody has named you as their trusted contact.</p>
        {:else}
          {#each view.received as g (g.sharing_id)}
            <div class="grant">
              <div class="who">
                <span class="mono selectable">{g.sharing_id}</span>
                <span class="small">
                  {#if g.stage === "idle"}
                    You can ask for access. It opens after {days(g.wait_days)} unless they deny it.
                  {:else if g.stage === "requested"}
                    Access opens on {when(g.release_at_ms)} unless they deny it.
                  {:else}
                    You have access, read-only.
                  {/if}
                </span>
              </div>
              {#if g.stage === "idle"}
                <button type="button" class="btn ghost sm" disabled={busy} onclick={() => request(g)}>
                  Ask for access
                </button>
              {:else}
                <button
                  type="button"
                  class="btn primary sm"
                  disabled={busy ||
                    (g.stage === "requested" &&
                      g.release_at_ms !== null &&
                      g.release_at_ms > Date.now())}
                  onclick={() => open(g)}
                >
                  Open their vaults
                </button>
              {/if}
            </div>
          {/each}
          <p class="small">
            Asking tells them in their app. Only ask if you really need to.
          </p>
        {/if}
      </section>
    {/if}
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
    width: min(620px, calc(100vw - 48px));
    max-height: calc(100vh - 48px);
    overflow-y: auto;
    padding: 28px 34px;
    display: flex;
    flex-direction: column;
    gap: 18px;
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
  .part {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .h2 {
    margin: 0;
  }
  .small {
    margin: 0;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .grant {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 12px 14px;
    border: 1px solid var(--hair);
    border-radius: 10px;
  }
  .who {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }
  .tag {
    font-size: 12px;
    padding: 3px 10px;
    border-radius: 999px;
    border: 1px solid var(--hair);
    white-space: nowrap;
  }
  .tag.warn {
    border-color: var(--accent);
    color: var(--accent);
  }
  .alert {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 12px 14px;
  }
  .row {
    display: flex;
    gap: 10px;
    justify-content: flex-end;
  }
  .start {
    align-self: flex-start;
  }
  .check {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .found {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: var(--accent);
  }
  .number {
    display: grid;
    grid-template-columns: repeat(6, auto);
    justify-content: start;
    gap: 6px 16px;
    font-size: 17px;
  }
  .match {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
  }
  select {
    width: 100%;
    background: transparent;
    color: inherit;
    border: none;
    font: inherit;
  }
  .danger {
    color: #ff8a8a;
  }
</style>
