// Steps forward on the phone (a page, a sheet) each add a history entry,
// so Android's back gesture closes them one at a time. Closing from a
// button goes through history too, to keep the two in step.

const open: (() => void)[] = [];

window.addEventListener("popstate", () => {
  open.pop()?.();
});

/** Records a step forward; `close` runs when the user steps back. */
export function opened(close: () => void): void {
  history.pushState({ blackboxus: open.length + 1 }, "");
  open.push(close);
}

/** Steps back once, closing the newest page or sheet. */
export function back(): void {
  if (open.length > 0) history.back();
}

/** Forgets every open step, for example after locking. */
export function reset(): void {
  const count = open.length;
  open.length = 0;
  if (count > 0) history.go(-count);
}
