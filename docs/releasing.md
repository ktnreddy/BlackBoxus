# Releasing

Releases are built by the **Release** workflow (`.github/workflows/release.yml`)
from a version tag. It only makes a **draft**: a person reads it and
publishes it.

## One-time setup

1. **Make the repository public** (Settings › General › Danger Zone ›
   Change visibility). The website's download buttons link to the latest
   release's files on GitHub, which only work for everyone on a public
   repository. Public repositories also get build attestations for free.
2. **Turn on private vulnerability reporting** (Settings › Code security ›
   Private vulnerability reporting), so the "Report a security problem
   privately" link and `SECURITY.md` work.
3. **The Android signing key.** Every APK must be signed with the same key,
   forever: Android refuses to install an update signed with another one,
   and if the key is lost, people have to uninstall (and lose the app's
   data) to move to a new one. Make it once:

   ```sh
   keytool -genkeypair -keystore blackboxus-upload.jks -storetype PKCS12 \
     -alias upload -keyalg RSA -keysize 3072 -validity 10000 \
     -dname "CN=BlackBoxus"
   base64 -w0 blackboxus-upload.jks   # on a Mac: base64 -i blackboxus-upload.jks
   ```

   Add two Actions secrets (Settings › Secrets and variables › Actions):
   `ANDROID_KEY_BASE64` (the base64 text) and `ANDROID_KEY_PASSWORD`.
   Keep the `.jks` file and its password somewhere safe and separate, such
   as an encrypted USB stick and a printed copy of the password. Without
   the secrets, the Release workflow stops rather than sign with a
   throwaway key.

## Each release

1. Pick the version: `0.x.y` while testing. Change it in `Cargo.toml`
   (`[workspace.package]` and the internal crates' requirements),
   `apps/desktop/src-tauri/tauri.conf.json`, `apps/desktop/package.json`,
   `apps/extension/package.json`, `apps/extension/static/manifest.json` and
   `apps/website/package.json`, then refresh the lock files
   (`cargo metadata` in the root and in `fuzz/`, `npm install` in each app).
2. Write the notes in `docs/releases/vX.Y.Z.md`: what to download, how to
   install, what's new, known limits.
3. Commit, push to `main`, and wait for **CI** to pass.
4. Tag that commit and push the tag:

   ```sh
   git tag -a v0.1.0 -m "BlackBoxus 0.1.0"
   git push origin v0.1.0
   ```

5. The Release workflow checks that the tag matches every version, that
   the commit is on `main` and that CI passed on it. Then it builds the
   Windows installer, the Linux packages, the signed Android APK and the
   extension zips from that commit, writes `SHA256SUMS.txt`, records build
   attestations (public repositories), and makes a draft release.
6. Open the draft under **Releases**. Install at least the Windows and
   Android files from it, check one checksum, then publish. It becomes
   the "latest" release, which the website's download buttons point to.
   (Pre-releases are skipped by those links, so test releases aren't
   marked as one; the notes say it's a test release instead.)

## If something goes wrong

- **Workflow failed:** fix it on `main`, delete the tag
  (`git push origin :refs/tags/v0.1.0` and `git tag -d v0.1.0`), and tag
  the new commit.
- **A published release has a serious bug:** publish the next version
  quickly, or delete the release so the buttons fall back to the one
  before. Never replace a file in
  a published release: people may already have checked its checksum.
