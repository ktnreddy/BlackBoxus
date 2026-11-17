// Talking to the BlackBoxus app through the native messaging host (spec
// section 14.2). Each exchange opens its own port, so a crash or a closed
// app cannot leave a stale connection behind.

export const HOST = "com.blackboxus.desktop";

/** A message from the app, before decryption. */
export type FromApp =
  | { t: "pair"; key: string }
  | { t: "paired" }
  | { t: "res"; n: string; c: string }
  | { t: "error"; code: string };

/** Why the app could not be reached, in a form the popup can explain. */
export class AppUnavailable extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

/** An open port that yields the app's messages one at a time. */
export class Connection {
  private readonly port: chrome.runtime.Port;
  private readonly queue: FromApp[] = [];
  private waiting: ((m: FromApp | null) => void) | null = null;
  private closed = false;

  constructor() {
    this.port = chrome.runtime.connectNative(HOST);
    this.port.onMessage.addListener((m: FromApp) => {
      if (this.waiting) {
        const w = this.waiting;
        this.waiting = null;
        w(m);
      } else {
        this.queue.push(m);
      }
    });
    this.port.onDisconnect.addListener(() => {
      this.closed = true;
      // Reading lastError marks it handled; the host is missing or exited.
      void chrome.runtime.lastError;
      this.waiting?.(null);
      this.waiting = null;
    });
  }

  send(message: unknown): void {
    this.port.postMessage(message);
  }

  /** The next message, or an error if none comes in `ms`. */
  next(ms: number): Promise<FromApp> {
    const ready = this.queue.shift();
    if (ready) return Promise.resolve(ready);
    if (this.closed) return Promise.reject(new AppUnavailable("not_installed"));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiting = null;
        reject(new AppUnavailable("timeout"));
      }, ms);
      this.waiting = (m) => {
        clearTimeout(timer);
        if (m) resolve(m);
        else reject(new AppUnavailable("not_installed"));
      };
    });
  }

  close(): void {
    if (!this.closed) this.port.disconnect();
    this.closed = true;
  }
}
