<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import { answerBrowserPairing, type PairingRequest } from "../api";

  /** A browser asking to pair. The user compares the code the extension
   *  shows; a different code means something else is asking. */
  let { request }: { request: PairingRequest } = $props();

  let busy = $state(false);

  async function answer(allow: boolean) {
    busy = true;
    await answerBrowserPairing(allow).catch(() => {});
  }
</script>

<div class="backdrop" role="presentation">
  <div class="card accent dialog" role="alertdialog" aria-modal="true" aria-labelledby="pair-title">
    <h1 id="pair-title" class="title">Allow {request.browser} to fill passwords?</h1>
    <p class="small">
      The BlackBoxus extension in {request.browser} is asking to connect. Allow it only if the
      extension shows this code:
    </p>
    <div class="code" aria-label={`Code ${request.code.split("").join(" ")}`}>
      {request.code.slice(0, 3)} {request.code.slice(3)}
    </div>
    <p class="small">
      Once allowed, it can ask for the login for the site you're on, while BlackBoxus is unlocked
      and only when you click fill. You can remove it in Settings.
    </p>
    <div class="row actions">
      <button type="button" class="btn ghost" disabled={busy} onclick={() => answer(false)}>
        <Icon name="x" size={15} />Don't allow
      </button>
      <button type="button" class="btn primary" disabled={busy} onclick={() => answer(true)}>
        <Icon name="check" size={15} />Allow
      </button>
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(5, 5, 6, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 20;
  }
  .dialog {
    width: min(500px, calc(100vw - 48px));
    padding: 28px 34px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    box-shadow: 0 50px 120px -40px rgba(0, 0, 0, 0.9);
  }
  .title {
    margin: 0;
    font-size: 26px;
    font-weight: 300;
    letter-spacing: -0.02em;
  }
  .small {
    margin: 0;
  }
  .code {
    font-family: var(--font-mono);
    font-size: 40px;
    letter-spacing: 0.12em;
    text-align: center;
    color: var(--accent);
    padding: 18px 0;
    border-radius: 18px;
    background: #111113;
    border: 1px solid var(--line);
  }
  .actions {
    justify-content: flex-end;
    gap: 12px;
  }
</style>
