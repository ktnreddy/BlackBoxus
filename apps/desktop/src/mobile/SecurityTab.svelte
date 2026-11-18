<script lang="ts">
  import { untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import Page from "./Page.svelte";
  import { opened } from "./nav";
  import type { IconName } from "./icons";
  import {
    errorMessage,
    passwordHealth,
    type Health,
    type HealthFinding,
    type VaultSummary,
  } from "../lib/api";

  let {
    vaults,
    onopen,
  }: {
    vaults: VaultSummary[];
    onopen: (vault: string, item: string) => void;
  } = $props();

  let health = $state<Health | null>(null);
  let checking = $state(false);
  let error = $state("");
  let checkedAt = $state<number | null>(null);

  /** A quick check on this phone first, then the leak check, which asks
   *  Have I Been Pwned with only a 5-character hash prefix per password. */
  async function check() {
    if (checking) return;
    checking = true;
    error = "";
    try {
      health = await passwordHealth(false);
      checkedAt = Date.now();
      health = await passwordHealth(true);
      checkedAt = Date.now();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      checking = false;
    }
  }

  $effect(() => {
    // Checks again after a save, when the vault list is replaced.
    void vaults;
    untrack(() => check());
  });

  type Kind = "leaked" | "reused" | "weak" | "two_step";
  const KINDS: { id: Kind; title: string; icon: IconName; tone: "red" | "amber" | "soft" }[] = [
    { id: "leaked", title: "Leaked passwords", icon: "alert", tone: "red" },
    { id: "reused", title: "Reused passwords", icon: "repeat", tone: "amber" },
    { id: "weak", title: "Weak passwords", icon: "lockOpen", tone: "amber" },
    { id: "two_step", title: "Two-step login available", icon: "phone", tone: "soft" },
  ];
  function desc(k: Kind, n: number) {
    if (k === "leaked") return health && !health.leaks_checked ? "Not checked yet" : "Seen in known data breaches";
    if (k === "reused") return n === 0 ? "Every login has its own" : `Same password on ${n} sites`;
    if (k === "two_step") return "Sites where you can add a one-time code";
    return "Short or easy to guess";
  }

  const has = (f: HealthFinding, k: Kind) =>
    k === "leaked" ? f.leaked !== null : k === "reused" ? f.reused > 0 : k === "weak" && f.weak;
  const count = (k: Kind) =>
    k === "two_step" ? (health?.two_step.length ?? 0) : (health?.findings.filter((f) => has(f, k)).length ?? 0);

  let list = $state<Kind | null>(null);
  function show(k: Kind) {
    list = k;
    opened(() => (list = null));
  }

  const verdict = $derived(
    !health
      ? ""
      : health.logins === 0
        ? "Nothing to check yet"
        : health.score >= 90
          ? "Looking good"
          : health.score >= 60
            ? "Good, with a few fixes"
            : "Needs attention",
  );
  const worst = $derived(health?.findings.find((f) => f.leaked !== null) ?? null);
  /** The ring: a circle of radius 42 with an 8px stroke fills 38 to 46. */
  const ARC = 2 * Math.PI * 42;
  const time = (t: number) =>
    new Date(t).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }).toLowerCase();
</script>

<header class="sc-head"><h1 class="sc-h1">Security</h1></header>
<div class="sc-main m-scroll">
  <div class="sc-summary">
    <div class="sc-ring" role="img" aria-label={`Score ${health?.score ?? 0} out of 100`}>
      <svg class="sc-arc" width="92" height="92" viewBox="0 0 92 92" aria-hidden="true">
        <circle cx="46" cy="46" r="42" fill="none" stroke="#2a2a2e" stroke-width="8" />
        <circle
          cx="46"
          cy="46"
          r="42"
          fill="none"
          stroke="#ff6a1a"
          stroke-width="8"
          stroke-dasharray={`${(ARC * (health?.score ?? 0)) / 100} ${ARC}`}
          transform="rotate(-90 46 46)"
        />
      </svg>
      <span class="sc-score">{health?.score ?? "–"}</span>
    </div>
    <div class="sc-text">
      <span class="sc-verdict">{checking && !health ? "Checking…" : verdict}</span>
      {#if health}
        <span class="sc-detail">
          {health.findings.length} of {health.logins} logins need attention.{checking
            ? " Checking for leaks…"
            : checkedAt
              ? ` Checked today, ${time(checkedAt)}.`
              : ""}
        </span>
      {/if}
    </div>
  </div>

  {#if error}<p class="m-error" role="alert">{error}</p>{/if}

  <div class="sc-group">
    {#each KINDS as k (k.id)}
      {@const n = count(k.id)}
      <button type="button" class="sc-row" onclick={() => show(k.id)} disabled={n === 0}>
        <span class="sc-icon {k.tone}"><Icon name={k.icon} size={21} weight={1.8} /></span>
        <span class="sc-grow">
          <span class="sc-title">{k.title}</span>
          <span class="sc-desc">{desc(k.id, n)}</span>
        </span>
        <span class="sc-count {k.tone}" class:zero={n === 0}>{n}</span>
      </button>
    {/each}
  </div>

  {#if worst}
    <div class="sc-worst">
      <div class="sc-who">
        <span class="sc-badge">{worst.title[0]?.toUpperCase() ?? "?"}</span>
        <span class="sc-grow">
          <span class="sc-title">{worst.title}</span>
          <span class="sc-bad">Found in a data breach</span>
        </span>
      </div>
      <button type="button" class="sc-fix" onclick={() => onopen(worst.vault, worst.item)}>
        Change this password
      </button>
    </div>
  {/if}

  <p class="sc-fine">
    Leak checks use Have I Been Pwned. Only the first 5 characters of a scrambled fingerprint leave
    your phone, never the password.
  </p>
</div>

{#if list && health}
  {@const k = KINDS.find((x) => x.id === list)}
  {@const found = list === "two_step" ? [] : health.findings.filter((f) => list && has(f, list))}
  <Page title={k?.title ?? ""} backLabel="Security">
    <p class="m-lede">
      {list === "two_step"
        ? "These sites can ask for a one-time code as well as your password, so a stolen password alone isn't enough. Turn it on in the site's security settings, then add the setup key here."
        : list === "reused"
          ? "If one of these sites is breached, attackers will try the same password on the others. Give each one its own."
          : list === "leaked"
            ? "These passwords are in lists attackers use. Change them first."
            : "These are short or easy to guess. A generated password is much stronger."}
    </p>
    <span class="sl-label">
      {list === "two_step"
        ? `${health.two_step.length} ${health.two_step.length === 1 ? "site" : "sites"}`
        : list === "reused"
          ? `These ${found.length} share passwords`
          : `${found.length} to fix`}
    </span>
    <div class="sc-group">
      {#if list === "two_step"}
        {#each health.two_step as t (t.vault + t.item)}
          <div class="sl-row">
            <span class="sc-badge">{t.title[0]?.toUpperCase() ?? "?"}</span>
            <span class="sc-grow">
              <span class="sc-title">{t.title}</span>
              <span class="sc-desc">{t.site}</span>
            </span>
            <button type="button" class="sl-fix" onclick={() => onopen(t.vault, t.item)}>Set up</button>
          </div>
        {/each}
      {:else}
        {#each found as f (f.vault + f.item)}
          <div class="sl-row">
            <span class="sc-badge">{f.title[0]?.toUpperCase() ?? "?"}</span>
            <span class="sc-grow">
              <span class="sc-title">{f.title}</span>
              <span class="sc-desc">
                {list === "leaked" ? `Seen ${f.leaked?.toLocaleString()} times in breaches` : f.subtitle || f.vault_name}
              </span>
            </span>
            <button type="button" class="sl-fix" onclick={() => onopen(f.vault, f.item)}>Fix</button>
          </div>
        {/each}
      {/if}
    </div>
    <div class="sl-note">
      <Icon name="info" size={22} />
      <span>
        {list === "two_step"
          ? "Set up opens the login for editing. Add one-time code, then paste the setup key the site shows."
          : "Fix opens the login for editing. Change the password on the website first, then save the new one here."}
      </span>
    </div>
  </Page>
{/if}

<style>
  .sc-head {
    padding: calc(52px + var(--sb)) 24px 0;
  }
  .sc-h1 {
    margin: 0;
    font-size: 30px;
    font-weight: 400;
    letter-spacing: -0.02em;
  }
  .sc-main {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 18px 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .sc-summary {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 20px;
    border-radius: 22px;
    background: #151517;
    border: 1px solid #1f1f22;
    flex: none;
  }
  .sc-ring {
    position: relative;
    width: 92px;
    height: 92px;
    flex: none;
    display: grid;
    place-items: center;
  }
  .sc-arc {
    position: absolute;
    inset: 0;
  }
  .sc-score {
    position: relative;
    width: 76px;
    height: 76px;
    border-radius: 38px;
    background: #151517;
    display: grid;
    place-items: center;
    font-size: 28px;
    font-weight: 500;
  }
  .sc-text {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .sc-verdict {
    font-size: 18px;
    font-weight: 500;
  }
  .sc-detail {
    font-size: 14px;
    line-height: 1.45;
    color: #a1a1aa;
  }
  .sc-group {
    background: #151517;
    border: 1px solid #1f1f22;
    border-radius: 20px;
    overflow: hidden;
    flex: none;
  }
  .sc-row {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 73px;
    padding: 0 16px;
    border: 0;
    border-bottom: 1px solid #1f1f22;
    background: none;
    color: #f4f4f5;
    font: inherit;
    text-align: left;
  }
  .sc-icon {
    width: 42px;
    height: 42px;
    border-radius: 12px;
    flex: none;
    display: grid;
    place-items: center;
  }
  .sc-icon.red {
    background: rgba(252, 165, 165, 0.12);
    color: #fca5a5;
  }
  .sc-icon.amber {
    background: rgba(255, 106, 26, 0.14);
    color: #ffb27f;
  }
  .sc-grow {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .sc-title {
    font-size: 16px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sc-desc {
    font-size: 13px;
    color: #a1a1aa;
  }
  .sl-row .sc-desc {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sc-count {
    min-width: 28px;
    height: 28px;
    padding: 0 9px;
    box-sizing: border-box;
    border-radius: 14px;
    display: grid;
    place-items: center;
    font-size: 14px;
    font-weight: 600;
  }
  .sc-count.red {
    background: rgba(252, 165, 165, 0.16);
    color: #fca5a5;
  }
  .sc-count.amber {
    background: rgba(255, 106, 26, 0.18);
    color: #ffb27f;
  }
  .sc-icon.soft {
    background: #1c1c1f;
    color: #d4d4d8;
  }
  .sc-count.soft {
    background: #1c1c1f;
    color: #d4d4d8;
  }
  .sc-count.zero {
    background: #1c1c1f;
    color: #d4d4d8;
  }
  .sc-worst {
    padding: 16px;
    border-radius: 20px;
    background: rgba(255, 106, 26, 0.1);
    border: 1px solid rgba(255, 106, 26, 0.38);
    display: flex;
    flex-direction: column;
    gap: 12px;
    flex: none;
  }
  .sc-who {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .sc-badge {
    width: 40px;
    height: 40px;
    flex: none;
    border-radius: 12px;
    background: #1c1c1f;
    display: grid;
    place-items: center;
    color: #ffb27f;
    font-weight: 600;
  }
  .sc-bad {
    font-size: 13px;
    color: #fca5a5;
  }
  .sc-fix {
    min-height: 48px;
    border: 0;
    border-radius: 24px;
    background: #ff6a1a;
    color: #140800;
    display: grid;
    place-items: center;
    font: 600 15px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    text-align: center;
  }
  .sc-fine {
    margin: 0 8px;
    font-size: 12px;
    line-height: 1.5;
    color: #71717a;
  }
  .sl-label {
    margin: 4px 8px 0;
    font-size: 13px;
    color: #a1a1aa;
  }
  .sl-row {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 68px;
    padding: 0 12px 0 16px;
    border-bottom: 1px solid #1f1f22;
  }
  .sl-fix {
    min-height: 40px;
    padding: 0 16px;
    border-radius: 20px;
    border: 1px solid #2a2a2e;
    background: none;
    display: grid;
    place-items: center;
    color: #f4f4f5;
    font: 500 14px "DM Sans Variable", sans-serif;
    padding-top: 6px;
    padding-bottom: 6px;
    line-height: 1.2;
    white-space: nowrap;
  }
  .sl-note {
    display: flex;
    gap: 12px;
    padding: 14px 16px;
    border-radius: 18px;
    background: #151517;
    border: 1px solid #1f1f22;
    font-size: 14px;
    line-height: 1.45;
    color: #d4d4d8;
    flex: none;
  }
  .sl-note > :global(svg) {
    flex: none;
    margin-top: 1px;
    color: #a1a1aa;
  }
</style>
