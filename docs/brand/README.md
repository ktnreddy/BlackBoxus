# Brand

- `icon.png`: the app icon, a white B with a keyhole on a black rounded
  tile. Every app's icons are made from it by resizing only: the desktop app
  (`apps/desktop/src-tauri/icons`), the Android launcher icons
  (`apps/desktop/src-tauri/gen/android/app/src/main/res/mipmap-*`), the
  in-app logo (`apps/desktop/public/logo.png`), the browser extension
  (`apps/extension/static/icons`) and the website (`apps/website/src`).
- `logo-glow.png`: the same icon with an orange glow around the tile. For
  banners, store listings and anywhere it is shown large on a dark
  background.

On Android the launcher cuts every icon to its own shape (circle, squircle
and so on). The adaptive icon places the whole of `icon.png` inside the
part every launcher shows, on black, so the mark keeps its size and place
whatever the shape. Phones with themed icons use the white mark alone.

Colours: orange `#FF6A1A`, near-black `#0B0B0C`, white `#F4F4F5`.
