<script lang="ts">
  import Icon from "./Icon.svelte";

  let {
    id,
    label,
    value = $bindable(""),
    autocomplete = "current-password",
    disabled = false,
    mono = true,
    size = "pw",
  }: {
    id: string;
    label: string;
    value?: string;
    autocomplete?: "current-password" | "new-password" | "off";
    disabled?: boolean;
    mono?: boolean;
    /** "big" in sign-up, "plain" when signing in, "pw" in settings. */
    size?: "big" | "plain" | "pw";
  } = $props();

  let shown = $state(false);
</script>

<div>
  <label class="m-label" for={id}>{label}</label>
  <div class="m-field {size === 'plain' ? '' : size}">
    <input
      {id}
      class:mono
      type={shown ? "text" : "password"}
      bind:value
      {autocomplete}
      {disabled}
      spellcheck="false"
      autocapitalize="off"
      autocorrect="off"
    />
    <button
      type="button"
      class="m-eye"
      aria-label={shown ? `Hide ${label}` : `Show ${label}`}
      aria-pressed={shown}
      onclick={() => (shown = !shown)}
    >
      <Icon name={shown ? "eyeOff" : "eye"} size={20} />
    </button>
  </div>
</div>
