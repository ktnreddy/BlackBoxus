<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "./Icon.svelte";
  import { cancelScan, errorMessage, isAppError, scanCode } from "../lib/api";

  /** Scans a QR code. The camera shows behind the app, so while this is
   *  open everything else is hidden and the page is see-through. */
  let {
    onscanned,
    onclose,
  }: { onscanned: (text: string) => void; onclose: (error?: string) => void } = $props();

  onMount(() => {
    document.documentElement.classList.add("m-scanning");
    let done = false;
    scanCode().then(
      (text) => {
        done = true;
        onscanned(text);
      },
      (e: unknown) => {
        done = true;
        onclose(isAppError(e) && e.code === "scan_cancelled" ? undefined : errorMessage(e));
      },
    );
    return () => {
      document.documentElement.classList.remove("m-scanning");
      if (!done) cancelScan().catch(() => {});
    };
  });
</script>

<div class="scan-overlay" role="dialog" aria-modal="true" aria-label="Scan a QR code">
  <p class="scan-hint">Point the camera at the QR code the site shows</p>
  <div class="scan-frame" aria-hidden="true"></div>
  <button type="button" class="scan-cancel" onclick={() => onclose()}>
    <Icon name="x" size={20} />Cancel
  </button>
</div>

<style>
  .scan-overlay {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 28px;
    padding: calc(48px + var(--sb)) 24px calc(40px + var(--bb));
    box-sizing: border-box;
    color: #f4f4f5;
  }
  .scan-hint {
    margin: 0;
    padding: 8px 14px;
    border-radius: 14px;
    background: rgba(11, 11, 12, 0.7);
    font-size: 15px;
    text-align: center;
  }
  .scan-frame {
    width: min(70vw, 280px);
    aspect-ratio: 1;
    border-radius: 24px;
    border: 3px solid #ff6a1a;
    /* Darkens the camera picture around the frame. */
    box-shadow: 0 0 0 100vmax rgba(5, 5, 6, 0.55);
  }
  .scan-cancel {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 52px;
    padding: 6px 24px;
    border: 0;
    border-radius: 26px;
    background: #151517;
    color: #f4f4f5;
    font: 500 16px "DM Sans Variable", sans-serif;
  }
</style>
