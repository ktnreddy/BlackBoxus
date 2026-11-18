<script lang="ts">
  import Icon from "./Icon.svelte";
  import Page from "./Page.svelte";
  import { back } from "./nav";
  import { tint } from "./tint";
  import {
    changeMemberRole,
    compareSafetyNumber,
    errorMessage,
    leaveVault,
    lookUpMember,
    removeMember,
    shareVault,
    vaultMembers,
    type LookedUp,
    type Member,
    type VaultSummary,
  } from "../lib/api";

  let {
    vault,
    onnotice,
    onchanged,
  }: {
    vault: VaultSummary;
    onnotice: (text: string) => void;
    onchanged: () => void;
  } = $props();

  const ROLES: Record<Member["role"], string> = {
    owner: "Owner",
    editor: "Can edit",
    viewer: "Can view",
  };

  let members = $state<Member[]>([]);
  let sharingId = $state("");
  let role = $state<"editor" | "viewer">("editor");
  let found = $state<LookedUp | null>(null);
  let comparing = $state<LookedUp | null>(null);
  let matched = $state(false);
  let selected = $state<Member | null>(null);
  let confirming = $state(false);
  let busy = $state(false);
  let error = $state("");

  const owner = $derived(members.some((m) => m.you && m.role === "owner"));

  $effect(() => {
    vaultMembers(vault.id).then(
      (m) => (members = m),
      (e: unknown) => (error = errorMessage(e)),
    );
  });

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
      comparing = null;
      matched = false;
      found = await lookUpMember(vault.id, sharingId.trim());
    });
  }

  function share() {
    if (!found || !matched) return;
    const id = found.sharing_id;
    run(async () => {
      members = await shareVault(vault.id, id, role);
      found = null;
      sharingId = "";
      matched = false;
      onnotice(`Shared ${vault.name}.`);
      onchanged();
    });
  }
</script>

<Page title="Members" backLabel={vault.name}>
  {#if owner}
    <form class="sp-add" onsubmit={lookUp}>
      <label class="sp-field">
        <span class="visually-hidden-m">Sharing ID of the person to add, from their Settings</span>
        <input id="sh-id" bind:value={sharingId} placeholder="Add someone by sharing ID" autocapitalize="off" spellcheck="false" disabled={busy} />
      </label>
      <button type="submit" class="sp-plus" aria-label="Look up" disabled={busy || !sharingId.trim()}>
        <Icon name="plus" size={22} weight={2.2} />
      </button>
    </form>
  {/if}

  {#if error}<p class="m-error" role="alert">{error}</p>{/if}

  <div class="sp-list">
    {#each members as m (m.sharing_id)}
      <button
        type="button"
        class="sp-row"
        onclick={() => {
          selected = selected?.sharing_id === m.sharing_id ? null : m;
          confirming = false;
        }}
      >
        <span class="sp-badge {tint(m.sharing_id)}">{m.you ? "Y" : (m.sharing_id.split("-")[1]?.[0]?.toUpperCase() ?? "?")}</span>
        <span class="sp-grow">
          <span class="sp-name">{m.you ? "You" : m.sharing_id}</span>
          <span class="sp-sub">{m.you ? m.sharing_id : "Sharing ID"}</span>
        </span>
        <span class="sp-role">{ROLES[m.role]}</span>
        <Icon name="next" size={16} />
      </button>
      {#if selected?.sharing_id === m.sharing_id}
        <div class="sp-actions">
          {#if !m.you}
            <button type="button" class="sp-small" disabled={busy} onclick={() => run(async () => {
              found = null;
              comparing = await compareSafetyNumber(m.sharing_id);
            })}>Safety number</button>
          {/if}
          {#if owner && !m.you}
            {#each ["editor", "viewer"] as const as r (r)}
              {#if m.role !== r}
                <button type="button" class="sp-small" disabled={busy} onclick={() => run(async () => {
                  members = await changeMemberRole(vault.id, m.sharing_id, r);
                  selected = null;
                  onnotice("Role changed.");
                })}>Make "{ROLES[r]}"</button>
              {/if}
            {/each}
            <button type="button" class="sp-small danger" disabled={busy} onclick={() => {
              if (!confirming) {
                confirming = true;
                return;
              }
              run(async () => {
                members = await removeMember(vault.id, m.sharing_id);
                selected = null;
                onnotice("Removed. The vault key was replaced and items re-encrypted.");
              });
            }}>{confirming ? "Tap again to remove" : "Remove"}</button>
          {/if}
          {#if m.you && !owner}
            <button type="button" class="sp-small danger" disabled={busy} onclick={() => {
              if (!confirming) {
                confirming = true;
                return;
              }
              run(async () => {
                await leaveVault(vault.id);
                onnotice(`You left ${vault.name}.`);
                onchanged();
                back();
              });
            }}>{confirming ? "Tap again to leave" : "Leave this vault"}</button>
          {/if}
        </div>
      {/if}
    {/each}
  </div>

  {#if found}
    <div class="sp-number">
      <span class="sp-ntitle">Check their safety number</span>
      <span class="sp-digits">{found.safety_number.join(" ")}</span>
      <span class="sp-nbody">Compare it with them in person or on a call before you share. If it matches, nobody slipped in their own key.</span>
      <div class="sp-two" role="radiogroup" aria-label="Role">
        <button type="button" class="sp-pill" role="radio" aria-checked={role === "editor"} onclick={() => (role = "editor")}>Can edit</button>
        <button type="button" class="sp-pill" role="radio" aria-checked={role === "viewer"} onclick={() => (role = "viewer")}>Can view</button>
      </div>
      <div class="sp-two">
        <button type="button" class="sp-ghost" disabled={busy} onclick={() => {
          found = null;
          sharingId = "";
          onnotice("Not shared. Check the sharing ID with them again.");
        }}>Doesn't match</button>
        <button type="button" class="sp-go" disabled={busy} onclick={() => {
          matched = true;
          share();
        }}>It matches</button>
      </div>
    </div>
  {/if}

  {#if comparing}
    <div class="sp-number">
      <span class="sp-ntitle">Safety number</span>
      <span class="sp-digits">{comparing.safety_number.join(" ")}</span>
      <span class="sp-nbody">It should match what they see for you.</span>
    </div>
  {/if}

  {#if owner}
    <p class="sp-fine">Removing someone replaces the vault key, so they can't read anything added later. Change passwords they could see.</p>
  {/if}
</Page>

<style>
  .sp-add {
    display: flex;
    gap: 8px;
    flex: none;
  }
  .sp-field {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    height: 52px;
    padding: 0 16px;
    border-radius: 26px;
    background: #151517;
    border: 1px solid #2a2a2e;
  }
  .sp-field:focus-within {
    border-color: #ff6a1a;
  }
  .sp-field input {
    flex: 1;
    width: 100%;
    min-width: 0;
    padding: 0;
    background: none;
    border: 0;
    outline: none;
    color: #f4f4f5;
    font: 400 16px "DM Sans Variable", sans-serif;
  }
  .visually-hidden-m {
    position: absolute;
    left: -9999px;
  }
  .sp-plus {
    width: 52px;
    height: 52px;
    flex: none;
    padding: 0;
    border-radius: 26px;
    border: 0;
    background: #ff6a1a;
    color: #140800;
    display: grid;
    place-items: center;
  }
  .sp-plus:disabled {
    opacity: 0.45;
  }
  .sp-list {
    background: #151517;
    border: 1px solid #1f1f22;
    border-radius: 20px;
    overflow: hidden;
    flex: none;
  }
  .sp-row {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 68px;
    padding: 0 16px;
    border: 0;
    border-bottom: 1px solid #1f1f22;
    background: none;
    color: #f4f4f5;
    font: inherit;
    text-align: left;
  }
  .sp-row :global(svg) {
    flex: none;
    color: #a1a1aa;
  }
  .sp-badge {
    width: 40px;
    height: 40px;
    flex: none;
    border-radius: 20px;
    background: #1c1c1f;
    display: grid;
    place-items: center;
    font-weight: 600;
  }
  .sp-grow {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .sp-name {
    font-size: 16px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sp-sub {
    font-size: 13px;
    color: #a1a1aa;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sp-role {
    font-size: 14px;
    color: #d4d4d8;
  }
  .sp-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding: 12px 16px;
    border-bottom: 1px solid #1f1f22;
  }
  .sp-small {
    min-height: 40px;
    padding: 0 16px;
    border-radius: 20px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #f4f4f5;
    font: 500 14px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .sp-small.danger {
    color: #fca5a5;
  }
  .sp-number {
    padding: 18px;
    border-radius: 20px;
    background: #151517;
    border: 1px solid rgba(255, 106, 26, 0.38);
    display: flex;
    flex-direction: column;
    gap: 10px;
    flex: none;
  }
  .sp-ntitle {
    font-size: 15px;
    font-weight: 500;
  }
  .sp-digits {
    font-family: var(--font-mono);
    font-size: 19px;
    letter-spacing: 1px;
    color: #ffb27f;
    user-select: text;
    -webkit-user-select: text;
  }
  .sp-nbody {
    font-size: 14px;
    line-height: 1.5;
    color: #d4d4d8;
  }
  .sp-two {
    display: grid;
    /* Side by side, or stacked when large text needs the room. */
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 9em), 1fr));
    gap: 10px;
    margin-top: 4px;
  }
  .sp-ghost,
  .sp-pill {
    min-height: 48px;
    border-radius: 24px;
    border: 1px solid #2a2a2e;
    background: none;
    color: #f4f4f5;
    font: 500 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .sp-pill[aria-checked="true"] {
    border-color: rgba(255, 106, 26, 0.38);
    background: rgba(255, 106, 26, 0.14);
    color: #ffb27f;
  }
  .sp-go {
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
  .sp-fine {
    margin: 0 8px;
    font-size: 13px;
    line-height: 1.5;
    color: #a1a1aa;
  }
</style>
