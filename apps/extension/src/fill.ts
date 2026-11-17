// The function injected into the page to fill a login. It runs in the
// extension's isolated world, in the top frame only, and only when the user
// asked from the toolbar or with the shortcut, never on its own. It fills
// only fields a person can see, and only if the page is still on the origin
// the app approved.

export type FillResult = "filled" | "wrong_origin" | "no_fields";

export function fillLogin(
  origin: string,
  username: string,
  password: string,
  totp: string | null,
): FillResult {
  if (location.origin !== origin) return "wrong_origin";

  const visible = (el: HTMLInputElement): boolean => {
    if (el.disabled || el.readOnly) return false;
    const box = el.getBoundingClientRect();
    if (box.width < 2 || box.height < 2) return false;
    for (let node: Element | null = el; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) < 0.1) {
        return false;
      }
    }
    return true;
  };
  const set = (el: HTMLInputElement, value: string) => {
    el.focus();
    // The native setter, so pages that track input with frameworks notice.
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const textual = (el: HTMLInputElement) => ["text", "email", "tel", ""].includes(el.type);

  const inputs = [...document.querySelectorAll("input")].filter(visible);
  const pw = inputs.find((i) => i.type === "password" && i.autocomplete !== "new-password") ??
    inputs.find((i) => i.type === "password");
  let filled = false;

  if (pw) {
    if (password) {
      set(pw, password);
      filled = true;
    }
    // The username is the nearest text field before the password field.
    const before = inputs.filter(
      (i) => textual(i) && i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING,
    );
    const scoped = pw.form ? before.filter((i) => i.form === pw.form) : before;
    const user = scoped.at(-1) ?? before.at(-1);
    if (user && username) {
      set(user, username);
      filled = true;
    }
    return filled ? "filled" : "no_fields";
  }

  // A one-time code step.
  const otp = inputs.find(
    (i) => i.autocomplete === "one-time-code" || /otp|totp|2fa|mfa/i.test(`${i.name} ${i.id}`),
  );
  if (otp && totp) {
    set(otp, totp);
    return "filled";
  }

  // A username step before the password is asked for.
  const user =
    inputs.find((i) => textual(i) && /username|email/.test(i.autocomplete)) ??
    inputs.find((i) => i.type === "email");
  if (user && username) {
    set(user, username);
    return "filled";
  }
  return "no_fields";
}
