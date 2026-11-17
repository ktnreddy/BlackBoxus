# BlackBoxus browser extension

Fills logins from the BlackBoxus desktop app in Chrome, Edge, Brave and
Firefox. It holds no keys and no vault: it asks the app for one login at a
time, when you click Fill, and the app answers only while unlocked and only with
logins saved for the page's site. See `docs/spec/14-browser-extension.md`
for the protocol and `docs/desktop.md` for how to load it.

```sh
npm ci
npm run check   # type-checks
npm test        # checks the crypto against docs/spec/vectors/14-browser.json
npm run build   # writes dist/ (Chrome, Edge, Brave) and dist-firefox/ (Firefox)
```

Permissions: `nativeMessaging` (to reach the app), `activeTab` and
`scripting` (to fill the current tab, only after you click or use the
shortcut). It has no content scripts and no access to any site by itself.
