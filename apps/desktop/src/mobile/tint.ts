// A steady colour for an item's letter badge, picked from its name, so the
// list is easier to scan. Classes rather than inline styles, because the
// app's content security policy allows no inline styles.

const COUNT = 7;

/** The tint class (`tint0` to `tint6`) for `name`. */
export function tint(name: string): string {
  let h = 0;
  for (const c of name) h = (h * 31 + (c.codePointAt(0) ?? 0)) >>> 0;
  return `tint${h % COUNT}`;
}
