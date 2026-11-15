<script lang="ts">
  import Icon from "./Icon.svelte";

  let {
    id,
    label,
    value = $bindable(""),
    autocomplete = "current-password",
    disabled = false,
  }: {
    id: string;
    label: string;
    value?: string;
    autocomplete?: "current-password" | "new-password";
    disabled?: boolean;
  } = $props();

  let shown = $state(false);
</script>

<div>
  <label class="label" for={id}>{label}</label>
  <div class="field">
    <input
      {id}
      type={shown ? "text" : "password"}
      bind:value
      {autocomplete}
      {disabled}
      spellcheck="false"
      autocapitalize="off"
    />
    <button
      type="button"
      class="icon-btn"
      aria-label={shown ? "Hide password" : "Show password"}
      aria-pressed={shown}
      onclick={() => (shown = !shown)}
    >
      <Icon name={shown ? "eyeOff" : "eye"} />
    </button>
  </div>
</div>
