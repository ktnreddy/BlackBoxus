<script lang="ts">
  import Icon from "./Icon.svelte";
  import NewPassword from "./NewPassword.svelte";
  import PasswordInput from "./PasswordInput.svelte";
  import StepHeader from "./StepHeader.svelte";
  import { back, opened } from "./nav";
  import {
    createAccount,
    errorMessage,
    recoverAccount,
    signIn,
    type AppStatus,
    type Created,
  } from "../lib/api";

  /** Welcome, sign-up, sign-in and recovery, before there is an account. */
  let {
    status,
    oncreated,
    onsignedin,
    onrecovered,
  }: {
    status: AppStatus;
    oncreated: (created: Created) => void;
    onsignedin: (status: AppStatus) => void;
    onrecovered: (created: Created) => void;
  } = $props();

  type Step = "email" | "password" | "signin" | "recover" | "recover-password";
  let steps = $state<Step[]>([]);
  const step = $derived(steps.at(-1) ?? null);

  function go(next: Step) {
    error = "";
    steps.push(next);
    opened(() => {
      steps.pop();
      error = "";
    });
  }

  let email = $state("");
  let password = $state("");
  let confirm = $state("");
  let ok = $state(false);
  let secretKey = $state("");
  let recoveryKey = $state("");
  let byContact = $state(false);
  let busy = $state(false);
  let error = $state("");

  const emailOk = $derived(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()));

  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (!ok || busy) return;
    busy = true;
    error = "";
    const [pw, again] = [password, confirm];
    try {
      const created = await createAccount(email.trim(), pw, again);
      password = "";
      confirm = "";
      oncreated(created);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function signInNow(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !emailOk || secretKey.trim() === "" || password === "") return;
    busy = true;
    error = "";
    const [key, pw] = [secretKey, password];
    password = "";
    try {
      onsignedin(await signIn(email.trim(), key, pw));
      secretKey = "";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function recover(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !emailOk || recoveryKey.trim() === "" || !ok) return;
    busy = true;
    error = "";
    const [key, pw, again] = [recoveryKey, password, confirm];
    password = "";
    confirm = "";
    try {
      onrecovered(await recoverAccount(email.trim(), key, pw, again));
      recoveryKey = "";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="m-fl wl">
  <main class="wl-main">
    <img class="wl-logo" src="/logo.png" alt="BlackBoxus" width="64" height="64" />
    <h1 class="wl-title">Your passwords, <span class="wl-hi">sealed.</span></h1>
    <p class="wl-lede">Everything is encrypted on this phone before it goes anywhere. Not even we can read it.</p>
    <div class="wl-facts">
      <div class="wl-fact"><Icon name="lock" size={20} />Only you hold the keys</div>
      <div class="wl-fact"><Icon name="shield" size={20} />Catches a server that lies</div>
      <div class="wl-fact"><Icon name="api" size={20} />Free and open source</div>
    </div>
  </main>
  <footer class="wl-foot">
    <button type="button" class="m-fl-btn" onclick={() => go("email")}>Create an account</button>
    <button type="button" class="m-fl-btn ghost" onclick={() => go("signin")}>I already have one</button>
  </footer>
</div>

{#if step === "email"}
  <form
    class="m-fl over"
    onsubmit={(e) => {
      e.preventDefault();
      if (emailOk) go("password");
    }}
  >
    <StepHeader step={1} onback={back} />
    <main class="m-fl-main su1">
      <p class="m-fl-step">Step 1 of 4</p>
      <h1 class="m-fl-title">What's your email?</h1>
      <p class="m-fl-lede gap18">It finds your account when you sign in. It's the only thing our server can read.</p>
      <label class="m-fl-field">
        <span class="m-fl-label">Email</span>
        <span class="m-field big">
          <input type="email" inputmode="email" bind:value={email} autocomplete="email" autocapitalize="off" spellcheck="false" />
        </span>
      </label>
    </main>
    <footer class="m-fl-foot su1-foot">
      <button type="submit" class="m-fl-btn" disabled={!emailOk}>Continue</button>
      <p class="su1-next">Next: your master password, then your Emergency Kit</p>
    </footer>
  </form>
{:else if step === "password"}
  <form class="m-fl over" onsubmit={create}>
    <StepHeader step={2} onback={back} />
    <main class="m-fl-main su2">
      <p class="m-fl-step">Step 2 of 4</p>
      <h1 class="m-fl-title">Choose a master password</h1>
      <p class="m-fl-lede gap8">Long beats clever. Nobody, including us, can reset it for you.</p>
      <NewPassword {email} bind:password bind:confirm bind:ok disabled={busy} size="big" />
      <p class="tip">Tip: four or five random words are easy to remember and hard to guess.</p>
      {#if error}<p class="m-error" role="alert">{error}</p>{/if}
    </main>
    <footer class="m-fl-foot">
      <button type="submit" class="m-fl-btn" disabled={!ok || busy}>{busy ? "Creating your account…" : "Continue"}</button>
    </footer>
  </form>
{:else if step === "signin"}
  <form class="m-fl over" onsubmit={signInNow}>
    <header class="m-fl-top"><button type="button" class="m-fl-back" aria-label="Back" onclick={back}><Icon name="back" size={22} /></button></header>
    <main class="m-fl-main">
      <h1 class="m-fl-title">Sign in on this phone</h1>
      <p class="m-fl-lede gap4">You'll need your Emergency Kit. The Secret Key in it is typed only once on this phone.</p>
      <label class="m-fl-field">
        <span class="m-fl-label">Email</span>
        <span class="m-field">
          <input type="email" inputmode="email" bind:value={email} autocomplete="email" autocapitalize="off" spellcheck="false" disabled={busy} />
        </span>
      </label>
      <PasswordInput id="si-password" label="Master password" size="plain" mono={false} bind:value={password} disabled={busy} />
      <label class="m-fl-field">
        <span class="m-fl-label">Secret Key, from your Emergency Kit</span>
        <span class="m-field">
          <input id="si-key" class="mono" bind:value={secretKey} placeholder="A3K7-QH2M-…" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" disabled={busy} />
        </span>
      </label>
      {#if error}<p class="m-error" role="alert">{error}</p>{/if}
    </main>
    <footer class="m-fl-foot gap6">
      <button type="submit" class="m-fl-btn" disabled={busy || !emailOk || secretKey.trim() === "" || password === ""}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
      <button type="button" class="m-fl-link" onclick={() => go("recover")} disabled={busy}>Forgot your master password?</button>
    </footer>
  </form>
{:else if step === "recover"}
  <form
    class="m-fl over"
    onsubmit={(e) => {
      e.preventDefault();
      if (!byContact && recoveryKey.trim() && emailOk) go("recover-password");
    }}
  >
    <header class="m-fl-top"><button type="button" class="m-fl-back" aria-label="Back" onclick={back}><Icon name="back" size={22} /></button></header>
    <main class="m-fl-main">
      <h1 class="m-fl-title">Forgot your master password?</h1>
      <p class="m-fl-lede gap6">Nobody can reset it for you, but there are two ways back in if you set them up.</p>
      <button type="button" class="rc-choice" class:on={!byContact} aria-pressed={!byContact} onclick={() => (byContact = false)}>
        <span class="rc-ic"><Icon name="key" size={24} /></span>
        <span class="rc-text"><span class="rc-main">Use my recovery key</span><span class="rc-sub">Works straight away</span></span>
      </button>
      <button type="button" class="rc-choice" class:on={byContact} aria-pressed={byContact} onclick={() => (byContact = true)}>
        <span class="rc-ic"><Icon name="users" size={24} /></span>
        <span class="rc-text"><span class="rc-main">Ask my trusted contact</span><span class="rc-sub">They can read your vaults after the waiting period you chose</span></span>
      </button>
      {#if byContact}
        <div class="m-note rc-gap">
          <Icon name="info" size={22} />
          <span>Ask them to open BlackBoxus, go to Settings › Trusted contact and ask for access. When the waiting period ends, they can read your vaults and help you move your passwords to a new account.</span>
        </div>
      {:else}
        {#if !emailOk}
          <label class="m-fl-field rc-gap">
            <span class="m-fl-label">Email</span>
            <span class="m-field">
              <input type="email" inputmode="email" bind:value={email} autocomplete="email" autocapitalize="off" spellcheck="false" />
            </span>
          </label>
        {/if}
        <div class="m-fl-field" class:rc-gap={emailOk}>
          <label class="m-fl-label" for="rc-key">Recovery key</label>
          <span class="m-field area">
            <textarea id="rc-key" rows="3" bind:value={recoveryKey} placeholder="Type the words or characters from your recovery key" spellcheck="false" autocapitalize="characters"></textarea>
          </span>
        </div>
      {/if}
    </main>
    {#if !byContact}
      <footer class="m-fl-foot">
        <button type="submit" class="m-fl-btn" disabled={!emailOk || recoveryKey.trim() === ""}>Continue</button>
      </footer>
    {/if}
  </form>
{:else if step === "recover-password"}
  <form class="m-fl over" onsubmit={recover}>
    <header class="m-fl-top"><button type="button" class="m-fl-back" aria-label="Back" onclick={back}><Icon name="back" size={22} /></button></header>
    <main class="m-fl-main">
      <h1 class="m-fl-title">Choose a new master password</h1>
      <p class="m-fl-lede gap8">Your vaults stay as they are. Other devices are signed out, and you'll get a new recovery key.</p>
      <NewPassword {email} bind:password bind:confirm bind:ok disabled={busy} label="New master password" size="big" />
      {#if error}<p class="m-error" role="alert">{error}</p>{/if}
    </main>
    <footer class="m-fl-foot">
      <button type="submit" class="m-fl-btn" disabled={busy || !ok}>{busy ? "Recovering…" : "Set the new password"}</button>
    </footer>
  </form>
{/if}

<style>
  .wl {
    background:
      radial-gradient(ellipse 80% 50% at 85% 100%, rgba(255, 106, 26, 0.16), transparent 70%),
      #0b0b0c;
  }
  .wl-main {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    /* 96px on a normal phone, less on short ones. */
    padding: calc(clamp(40px, calc(100vh - 748px), 96px) + var(--sb)) 28px 0;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }
  .wl-logo {
    width: 64px;
    height: 64px;
    border-radius: 18px;
  }
  .wl-title {
    margin: 24px 0 0;
    font-size: min(52px, 13.4vw);
    line-height: 1.02;
    font-weight: 300;
    letter-spacing: -0.04em;
  }
  .wl-hi {
    color: #ff6a1a;
  }
  .wl-lede {
    margin: 0;
    font-size: 17px;
    line-height: 1.55;
    color: #d4d4d8;
  }
  .wl-main > * {
    flex: none;
  }
  .wl-facts {
    margin-top: 12px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .wl-fact {
    display: flex;
    gap: 12px;
    align-items: center;
    font-size: 15px;
    color: #d4d4d8;
  }
  .wl-fact :global(svg) {
    color: #ff6a1a;
  }
  .wl-foot {
    padding: 16px 24px calc(36px + var(--bb));
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .su1 {
    padding-top: 28px;
  }
  .su2 {
    padding-top: 24px;
  }
  .gap18 {
    margin-bottom: 18px;
  }
  .gap8 {
    margin-bottom: 8px;
  }
  .gap6 {
    margin-bottom: 6px;
  }
  .gap4 {
    margin-bottom: 4px;
  }
  .su1-foot {
    gap: 14px;
    align-items: center;
  }
  .su1-next {
    margin: 0;
    font-size: 14px;
    color: #a1a1aa;
  }
  footer.gap6 {
    margin: 0;
    gap: 6px;
  }
  .tip {
    margin: 0 4px;
    font-size: 14px;
    color: #a1a1aa;
    line-height: 1.5;
  }
  .rc-choice {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 18px;
    border-radius: 20px;
    border: 1px solid #1f1f22;
    background: #151517;
    color: #f4f4f5;
    font: inherit;
    text-align: left;
    box-sizing: content-box;
  }
  .rc-choice.on {
    border-color: rgba(255, 106, 26, 0.38);
  }
  .rc-ic {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    background: #1c1c1f;
    color: #d4d4d8;
    display: grid;
    place-items: center;
    flex: none;
  }
  .on .rc-ic {
    background: rgba(255, 106, 26, 0.14);
    color: #ffb27f;
  }
  .rc-text {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .rc-main {
    font-size: 17px;
    font-weight: 500;
  }
  .rc-sub {
    font-size: 14px;
    color: #a1a1aa;
  }
  .rc-gap {
    margin-top: 10px;
  }
</style>
