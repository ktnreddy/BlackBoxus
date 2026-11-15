<script lang="ts">
  import Icon from "../../components/Icon.svelte";
  import {
    compareSafetyNumber,
    copyText,
    errorMessage,
    lookUpMember,
    mySharingId,
    shareVault,
    vaultMembers,
    type LookedUp,
    type Member,
    type VaultSummary,
  } from "../../api";

  let {
    vault,
    onclose,
    onnotice,
  }: { vault: VaultSummary; onclose: () => void; onnotice: (text: string) => void } = $props();

  const ROLES: Record<Member["role"], string> = {
    owner: "Owner",
    editor: "Can edit",
    viewer: "Can view",
  };

  let members = $state<Member[]>([]);
  let mine = $state("");
  let sharingId = $state("");
  let role = $state<"editor" | "viewer">("editor");
  let found = $state<LookedUp | null>(null);
  /** A safety number shown for an existing member, to compare. */
  let comparing = $state<LookedUp | null>(null);
  let matched = $state(false);
  let busy = $state(false);
  let error = $state("");

  const owner = $derived(members.some((m) => m.you && m.role === "owner"));

  $effect(() => {
    const id = vault.id;
    vaultMembers(id).then(
      (m) => (members = m),
      (e: unknown) => (error = errorMessage(e)),
    );
    mySharingId().then((s) => (mine = s));
  });

  async function lookUp(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !sharingId.trim()) return;
    busy = true;
    error = "";
    found = null;
    comparing = null;
    matched = false;
    try {
      found = await lookUpMember(vault.id, sharingId);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function share() {
    if (!found || !matched || busy) return;
    busy = true;
    error = "";
    try {
      members = await shareVault(vault.id, found.sharing_id, role);
      onnotice(`Shared ${vault.name}.`);
      found = null;
      sharingId = "";
      matched = false;
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function compare(member: Member) {
    busy = true;
    error = "";
    found = null;
    try {
      comparing = await compareSafetyNumber(member.sharing_id);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function copyMine() {
    try {
      await copyText(mine);
      onnotice("Your sharing ID was copied.");
    } catch (e) {
      onnotice(errorMessage(e));
    }
  }

  const shown = $derived(found ?? comparing);
</script>

<div class="share">
  <section class="left">
    <button type="button" class="btn ghost sm back" onclick={onclose}>
      <Icon name="arrowLeft" size={15} />Back to items
    </button>
    <h1 class="display heading">Share <span class="hi">{vault.name}</span></h1>
    <p class="lede">People you add can open every item in this vault.</p>

    {#if owner}
      <form class="add" onsubmit={lookUp}>
        <div>
          <label class="label" for="sharing-id">Their sharing ID</label>
          <div class="field">
            <input
              id="sharing-id"
              class="mono"
              bind:value={sharingId}
              placeholder="XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
              autocomplete="off"
              spellcheck="false"
              disabled={busy}
            />
            <button type="submit" class="btn ghost sm" disabled={busy || !sharingId.trim()}>
              Look up
            </button>
          </div>
          <p class="small hint">They'll find it on their own Share screen.</p>
        </div>
        <div>
          <span class="label" id="role-label">Role</span>
          <div class="seg" role="group" aria-labelledby="role-label">
            <button type="button" aria-pressed={role === "editor"} onclick={() => (role = "editor")}
              >Can edit</button
            >
            <button type="button" aria-pressed={role === "viewer"} onclick={() => (role = "viewer")}
              >Can view</button
            >
          </div>
        </div>
      </form>
    {/if}

    <div>
      <div class="small members-label">Members</div>
      <ul class="members">
        {#each members as m (m.sharing_id)}
          <li>
            <span class="avatar" aria-hidden="true"><Icon name="users" size={16} /></span>
            <span class="who">
              <span class="name">{m.you ? "You" : "Member"}</span>
              <span class="small mono">{m.sharing_id}</span>
            </span>
            {#if !m.you}
              <button type="button" class="btn ghost sm" disabled={busy} onclick={() => compare(m)}
                >Compare</button
              >
            {/if}
            <span class="chip">{ROLES[m.role]}</span>
          </li>
        {/each}
      </ul>
    </div>

    <div class="mine">
      <span class="small">Your sharing ID</span>
      <span class="mono selectable">{mine}</span>
      <button type="button" class="icon-btn" aria-label="Copy your sharing ID" onclick={copyMine}>
        <Icon name="copy" />
      </button>
    </div>
  </section>

  <section class="right">
    {#if error}
      <p class="note" role="alert"><Icon name="alert" />{error}</p>
    {/if}
    {#if shown}
      <div class="card accent check" aria-label="Safety number">
        <span class="found"><Icon name="shield" size={15} />Their keys were found in the public key log</span>
        <h2 class="h2">Check the safety number</h2>
        <p class="small explain">
          Compare it with them in person or on a call. It is the same on both of your screens only if
          nobody has swapped the keys. They'll see it under Compare on their Share screen.
        </p>
        <div class="number mono" aria-label="Safety number">
          {#each shown.safety_number as group, i (i)}<span>{group}</span>{/each}
        </div>
        {#if found}
          <label class="match">
            <input type="checkbox" bind:checked={matched} />
            We compared it and it matches
          </label>
          <div class="rule"></div>
          <div class="row actions">
            <button type="button" class="btn ghost" onclick={() => (found = null)}>Cancel</button>
            <button type="button" class="btn primary" disabled={!matched || busy} onclick={share}>
              {busy ? "Sharing…" : "Share"}
            </button>
          </div>
        {:else}
          <div class="row actions">
            <button type="button" class="btn ghost" onclick={() => (comparing = null)}>Done</button>
          </div>
        {/if}
      </div>
    {:else}
      <div class="empty">
        <p class="lede">
          {owner
            ? "Enter their sharing ID and look them up. You'll compare a safety number before anything is shared."
            : "Only the vault's owner can add people. You can compare safety numbers with any member."}
        </p>
      </div>
    {/if}
  </section>
</div>

<style>
  .share {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 48px;
    min-height: 100%;
  }
  .left,
  .right {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }
  .right {
    justify-content: center;
  }
  .back {
    align-self: flex-start;
  }
  .heading {
    font-size: 48px;
    overflow-wrap: anywhere;
  }
  .add {
    display: flex;
    flex-direction: column;
    gap: 18px;
  }
  .hint {
    margin: 6px 0 0;
    padding: 0 8px;
  }
  .seg {
    display: inline-flex;
    padding: 4px;
    border-radius: 999px;
    background: #111113;
    border: 1px solid var(--line);
    gap: 2px;
  }
  .seg button {
    height: 34px;
    padding: 0 16px;
    border: 0;
    border-radius: 999px;
    background: transparent;
    color: var(--muted);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
  }
  .seg button[aria-pressed="true"] {
    background: var(--text);
    color: #111113;
  }
  .members-label {
    margin-bottom: 4px;
  }
  .members {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .members li {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
    border-top: 1px solid var(--hair);
  }
  .avatar {
    width: 36px;
    height: 36px;
    border-radius: 12px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--muted);
    flex: none;
  }
  .who {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .who .mono {
    font-size: 12px;
  }
  .name {
    font-size: 15px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    height: 28px;
    padding: 0 12px;
    border-radius: 999px;
    font-size: 13px;
    background: var(--panel-2);
    color: var(--soft);
    white-space: nowrap;
  }
  .mine {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: 16px;
    border: 1px dashed var(--line);
    font-size: 14px;
  }
  .mine .mono {
    flex: 1;
  }
  .check {
    padding: 30px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .found {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 12px;
    border-radius: 999px;
    font-size: 13px;
    background: #0f2117;
    color: var(--good);
  }
  .explain {
    margin: 0;
    font-size: 14px;
  }
  .number {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px 8px;
    padding: 20px 22px;
    border-radius: 18px;
    background: #0e0e10;
    border: 1px solid var(--line);
    font-size: 19px;
    text-align: center;
  }
  .match {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 15px;
    cursor: pointer;
  }
  .match input {
    width: 20px;
    height: 20px;
    margin: 0;
    accent-color: var(--accent);
  }
  .actions {
    justify-content: flex-end;
  }
  .empty {
    max-width: 420px;
  }
</style>
