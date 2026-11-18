// What iPhones and iPads need that Android does for us:
//
// - The keyboard. iOS doesn't shrink the page when the keyboard opens (Android
//   does, with adjustResize); it slides the whole page up instead, header and
//   all. Here the app's frame is shrunk to the part above the keyboard, so
//   the screens lay out just as they do on Android.
// - Text size. iOS web views ignore the system text size (Dynamic Type)
//   unless asked. The size is read from the system's body font and applied
//   like Android's text zoom, which the screens are already tested with.
// - Going back. iPhones have no back button; swiping in from the left edge
//   steps back, as in other iPhone apps.
// - Zooming into fields. iOS zooms the page when a field is focused unless
//   the page can't be zoomed.
// - The app switcher. iOS has no screenshot block like Android's; the
//   screen is covered as soon as the app goes to the background, so its
//   snapshot in the app switcher shows no vault contents.

import { back, canGoBack } from "./nav";

let started = false;

/** Turns on the iOS behaviour. Safe to call more than once. */
export function startIOS(): void {
  if (started) return;
  started = true;
  const root = document.documentElement;
  root.classList.add("ios");
  noFieldZoom();
  followKeyboard(root);
  followTextSize(root);
  edgeSwipeBack();
  coverWhenAway(root);
}

function coverWhenAway(root: HTMLElement): void {
  const set = (away: boolean) => root.classList.toggle("away", away);
  document.addEventListener("visibilitychange", () => set(document.visibilityState !== "visible"));
  window.addEventListener("pagehide", () => set(true));
  window.addEventListener("pageshow", () => set(false));
}

function noFieldZoom(): void {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="viewport"]');
  if (meta && !meta.content.includes("maximum-scale")) {
    meta.content += ", maximum-scale=1";
  }
}

function followKeyboard(root: HTMLElement): void {
  const vv = window.visualViewport;
  if (!vv) return;
  const update = () => {
    // What the keyboard (or anything else) covers at the bottom.
    const covered = Math.max(0, Math.round(window.innerHeight - vv.height - vv.offsetTop));
    root.style.setProperty("--kb", `${covered}px`);
    root.classList.toggle("kb", covered > 80);
    // iOS scrolls the page to show the field; the frame is already sized
    // to fit, so put it back.
    if (window.scrollY !== 0 || vv.offsetTop !== 0) window.scrollTo(0, 0);
  };
  vv.addEventListener("resize", update);
  vv.addEventListener("scroll", update);
  update();
}

/** The default iOS body text size ("Large"), in CSS pixels. */
const DEFAULT_BODY = 17;

function followTextSize(root: HTMLElement): void {
  const probe = document.createElement("span");
  probe.className = "dt-probe";
  probe.textContent = "A";
  probe.setAttribute("aria-hidden", "true");
  document.body.appendChild(probe);
  const apply = () => {
    const size = parseFloat(getComputedStyle(probe).fontSize);
    if (!Number.isFinite(size) || size <= 0) return;
    // Smaller than default is kept a little larger than iOS would make it,
    // and the largest accessibility sizes are capped where the screens
    // still work (they are tested up to 160%).
    const ratio = Math.min(2, Math.max(0.9, size / DEFAULT_BODY));
    root.style.setProperty("-webkit-text-size-adjust", `${Math.round(ratio * 100)}%`);
    root.style.setProperty("text-size-adjust", `${Math.round(ratio * 100)}%`);
  };
  apply();
  // People change it in the Settings app, then come back.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") apply();
  });
}

function edgeSwipeBack(): void {
  /** How close to the left edge a swipe must start. */
  const EDGE = 24;
  let start: { x: number; y: number; t: number } | null = null;
  window.addEventListener(
    "touchstart",
    (e) => {
      const touch = e.touches[0];
      start =
        e.touches.length === 1 && touch && touch.clientX <= EDGE && canGoBack()
          ? { x: touch.clientX, y: touch.clientY, t: e.timeStamp }
          : null;
    },
    { passive: true },
  );
  window.addEventListener(
    "touchend",
    (e) => {
      const touch = e.changedTouches[0];
      if (!start || !touch) return;
      const dx = touch.clientX - start.x;
      const dy = Math.abs(touch.clientY - start.y);
      const quick = e.timeStamp - start.t < 600;
      start = null;
      // Far enough, mostly sideways: a third of the screen, or a flick.
      if (dy < dx * 0.6 && (dx > window.innerWidth / 3 || (quick && dx > 60))) back();
    },
    { passive: true },
  );
  window.addEventListener("touchcancel", () => (start = null), { passive: true });
}
