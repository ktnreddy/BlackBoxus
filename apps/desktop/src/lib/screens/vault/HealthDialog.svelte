<script lang="ts">
  import { untrack } from "svelte";
  import Icon from "../../components/Icon.svelte";
  import { errorMessage, passwordHealth, type Health, type HealthFinding } from "../../api";

  /** Password health: weak, reused and leaked passwords. The passwords
   *  are checked in Rust; this only gets the findings. */
  let {
    onfix,
    onclose,
  }: {
    /** Opens the item's editor so the password can be changed. */
    onfix: (vault: string, item: string) => void;
    onclose: () => void;
  } = $props();

  type Kind = "leaked" | "reused" | "weak" | "two_step";
  let health = $state<Health | null>(null);
  let checking = $state(false);
  let error = $state("");
  let kind = $state<Kind>("leaked");

  async function check() {
    if (checking) return;
    checking = true;
    error = "";
    try {
      health = await passwordHealth(false);
      health = await passwordHealth(true);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      checking = false;
    }
  }
  $effect(() => {
    untrack(() => check());
  });

  const has = (f: HealthFinding, k: Kind) =>
    k === "leaked" ? f.leaked !== null && f.leaked > 0 : k === "reused" ? f.reused > 0 : k === "weak" && f.weak;
  const count = (k: Kind) =>
    k === "two_step" ? (health?.two_step.length ?? 0) : (health?.findings.filter((f) => has(f, k)).length ?? 0);
  /** Rows for the chosen kind, in one shape. */
  const shown = $derived(
    kind === "two_step"
      ? (health?.two_step.map((t) => ({ vault: t.vault, item: t.item, title: t.title, sub: t.site, leaked: null })) ?? [])
      : (health?.findings
          .filter((f) => has(f, kind))
          .map((f) => ({ vault: f.vault, item: f.item, title: f.title, sub: f.subtitle || f.vault_name, leaked: f.leaked })) ?? []),
  );
  const KINDS: { id: Kind; title: string; why: string }[] = [
    { id: "leaked", title: "Leaked", why: "Seen in known data breaches. Change these first." },
    { id: "reused", title: "Reused", why: "If one site is breached, attackers try the same password on the others." },
    { id: "weak", title: "Weak", why: "Short or easy to guess. A generated password is much stronger." },
    {
      id: "two_step",
      title: "Two-step available",
      why: "These sites can also ask for a one-time code. Turn it on in the site's security settings, then add the setup key to the login.",
    },
  ];
  const verdict = $derived(
    !health ? "" : health.score >= 90 ? "Looking good" : health.score >= 70 ? "Good, with a few fixes" : "Needs attention",
  );

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Escape") onclose();
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop" role="presentation">
  <div class="card accent dialog" role="dialog" aria-modal="true" aria-labelledby="health-title">
    <div class="top">
      <h1 id="health-title" class="title">Password health</h1>
      <button type="button" class="icon-btn" aria-label="Close" onclick={onclose}><Icon name="x" /></button>
    </div>

    <div class="summary">
      <span class="score" class:dim={!health}>{health?.score ?? "–"}</span>
      <span class="text">
        <span class="verdict">{checking && !health ? "Checking…" : verdict}</span>
        {#if health}
          <span class="small">
            {health.findings.length} of {health.logins} logins need attention.{checking
              ? " Checking for leaks…"
              : health.leaks_checked
                ? ""
                : " Leaks weren't checked: no connection."}
          </span>
        {/if}
      </span>
    </div>

    {#if error}<p class="note" role="alert"><Icon name="alert" />{error}</p>{/if}

    <div class="tabs" role="tablist" aria-label="Kind">
      {#each KINDS as k (k.id)}
        <button type="button" role="tab" class="tab" aria-selected={kind === k.id} onclick={() => (kind = k.id)}>
          {k.title}<span class="n" class:bad={k.id === "leaked" && count(k.id) > 0}>{count(k.id)}</span>
        </button>
      {/each}
    </div>
    <p class="small">{KINDS.find((k) => k.id === kind)?.why}</p>

    <ul class="list">
      {#each shown as f (f.vault + f.item)}
        <li class="row-item">
          <span class="letter" aria-hidden="true">{f.title.slice(0, 1).toUpperCase()}</span>
          <span class="grow">
            <span class="name">{f.title}</span>
            <span class="small sub">
              {kind === "leaked" && f.leaked ? `Seen ${f.leaked.toLocaleString()} times · ` : ""}{f.sub}
            </span>
          </span>
          <button type="button" class="btn ghost sm" onclick={() => onfix(f.vault, f.item)}>{kind === "two_step" ? "Set up" : "Fix"}</button>
        </li>
      {:else}
        {#if health}<li class="small none"><Icon name="check" size={16} />Nothing to fix here.</li>{/if}
      {/each}
    </ul>

    <p class="small fine">
      Leak checks use Have I Been Pwned. Only the first 5 characters of a scrambled fingerprint of each
      password leave this computer, never the password.
    </p>
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
    gap: 16px;
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
  .small {
    margin: 0;
  }
  .summary {
    display: flex;
    align-items: center;
    gap: 18px;
  }
  .score {
    width: 72px;
    height: 72px;
    flex: none;
    border-radius: 50%;
    border: 6px solid var(--accent);
    display: grid;
    place-items: center;
    font-size: 24px;
    font-weight: 500;
  }
  .score.dim {
    border-color: var(--line);
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .verdict {
    font-size: 18px;
    font-weight: 500;
  }
  .tabs {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .tab {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border-radius: 999px;
    border: 1px solid var(--line);
    background: none;
    color: var(--soft);
    font: inherit;
    cursor: pointer;
  }
  .tab[aria-selected="true"] {
    border-color: var(--accent-line);
    background: rgba(255, 106, 26, 0.12);
    color: var(--accent-soft);
  }
  .n {
    min-width: 20px;
    padding: 0 6px;
    border-radius: 10px;
    background: var(--panel-2);
    color: var(--text);
    font-size: 12px;
    text-align: center;
  }
  .n.bad {
    color: #fca5a5;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .row-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 4px;
    border-bottom: 1px solid var(--hair);
  }
  .letter {
    width: 34px;
    height: 34px;
    flex: none;
    border-radius: 10px;
    background: var(--panel-2);
    display: grid;
    place-items: center;
    color: var(--accent-soft);
    font-weight: 600;
  }
  .grow {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .name,
  .sub {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name {
    font-weight: 500;
  }
  .none {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 4px;
  }
  .fine {
    color: var(--muted);
  }
</style>
