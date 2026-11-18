import type { AppStatus } from "./api";

/** The words the screens use for the device's own unlock method. */
export interface UnlockWords {
  /** As a name: "Face ID", "Touch ID", "fingerprint", "Windows Hello". */
  name: string;
  /** "Face ID unlock", "Fingerprint unlock", … at the start of a sentence. */
  Unlock: string;
  /** "Face ID unlock", "fingerprint unlock", … mid-sentence. */
  unlock: string;
  /** What the check uses: "your face", "your fingerprint". */
  yours: string;
  /** What gets enrolled: "faces", "fingerprints". */
  things: string;
  /** "iPhone", "iPad", "Mac", "phone", "computer". */
  device: string;
  /** Where it is set up, for "… in {where}". */
  where: string;
  /** The icon to show. */
  icon: "fingerprint" | "face" | "hello";
  /** The prompt shown while waiting: "Look at your iPhone", … */
  waiting: string;
}

function appleDevice(platform: string): string {
  if (platform === "macos") return "Mac";
  // iPadOS reports itself as a Mac with touch.
  const ua = typeof navigator === "undefined" ? "" : navigator.userAgent;
  const touchMac = typeof navigator !== "undefined" && /Macintosh/.test(ua) && navigator.maxTouchPoints > 1;
  return /iPad/.test(ua) || touchMac ? "iPad" : "iPhone";
}

export function unlockWords(status: Pick<AppStatus, "hello" | "platform">): UnlockWords {
  const platform = status.platform ?? "";
  switch (status.hello.kind) {
    case "face_id": {
      const device = appleDevice(platform);
      return {
        name: "Face ID",
        Unlock: "Face ID unlock",
        unlock: "Face ID unlock",
        yours: "your face",
        things: "faces",
        device,
        where: `your ${device}'s Settings, under Face ID & Passcode`,
        icon: "face",
        waiting: `Look at your ${device}…`,
      };
    }
    case "touch_id": {
      const device = appleDevice(platform);
      return {
        name: "Touch ID",
        Unlock: "Touch ID unlock",
        unlock: "Touch ID unlock",
        yours: "your fingerprint",
        things: "fingerprints",
        device,
        where:
          device === "Mac"
            ? "System Settings, under Touch ID & Password"
            : `your ${device}'s Settings, under Touch ID & Passcode`,
        icon: "fingerprint",
        waiting: "Touch the sensor…",
      };
    }
    case "fingerprint":
      return {
        name: "fingerprint",
        Unlock: "Fingerprint unlock",
        unlock: "fingerprint unlock",
        yours: "your fingerprint",
        things: "fingerprints",
        device: "phone",
        where: "your phone's Settings",
        icon: "fingerprint",
        waiting: "Waiting for your fingerprint…",
      };
    default:
      return {
        name: "Windows Hello",
        Unlock: "Windows Hello",
        unlock: "Windows Hello",
        yours: "your face, fingerprint or PIN",
        things: "sign-in methods",
        device: "computer",
        where: "Windows Settings, under Accounts › Sign-in options",
        icon: "hello",
        waiting: "Waiting for Windows Hello…",
      };
  }
}
