//! Native messaging host mode (spec section 14.2). The browser starts this
//! app's executable with the extension's origin as an argument; it then
//! relays messages between the browser (standard input and output) and the
//! running app (the local socket), and does nothing else. It holds no keys
//! and reads no files.

use std::io::{self, BufReader, Write};
use std::thread;

use interprocess::local_socket::Stream;
use interprocess::local_socket::prelude::*;

use super::protocol::{MAX_MESSAGE_BYTES, MAX_REPLY_BYTES, read_frame, write_frame};
use super::socket_name;

/// Whether the browser started this process as a native messaging host.
pub fn launched_by_browser(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|a| a.starts_with("chrome-extension://"))
}

fn connect() -> io::Result<Stream> {
    #[cfg(windows)]
    let name = socket_name().to_ns_name::<interprocess::local_socket::GenericNamespaced>()?;
    #[cfg(not(windows))]
    let path = socket_name();
    #[cfg(not(windows))]
    let name = path
        .as_str()
        .to_fs_name::<interprocess::local_socket::GenericFilePath>()?;
    Stream::connect(name)
}

/// Relays until either side closes. If the app is not running, or its
/// browser integration is off, answers every message with an error the
/// extension can explain.
pub fn relay() {
    let Ok(app) = connect() else {
        let mut stdin = io::stdin().lock();
        let mut stdout = io::stdout().lock();
        let closed = br#"{"t":"error","code":"app_closed"}"#;
        while let Ok(Some(_)) = read_frame(&mut stdin, MAX_MESSAGE_BYTES) {
            if write_frame(&mut stdout, closed, MAX_REPLY_BYTES).is_err() {
                break;
            }
        }
        return;
    };
    let app = std::sync::Arc::new(app);
    let from_app = std::sync::Arc::clone(&app);
    // App to browser, on its own thread.
    thread::spawn(move || {
        let mut reader = BufReader::new(&*from_app);
        let mut stdout = io::stdout().lock();
        while let Ok(Some(frame)) = read_frame(&mut reader, MAX_REPLY_BYTES) {
            if write_frame(&mut stdout, &frame, MAX_REPLY_BYTES).is_err() {
                break;
            }
        }
        // The app went away: end, so the browser sees the port close.
        std::process::exit(0);
    });
    // Browser to app. When the browser closes the port, return and let
    // the process exit, which closes the socket.
    let mut stdin = io::stdin().lock();
    let mut to_app = &*app;
    while let Ok(Some(frame)) = read_frame(&mut stdin, MAX_MESSAGE_BYTES) {
        if write_frame(&mut to_app, &frame, MAX_MESSAGE_BYTES).is_err() {
            break;
        }
    }
    let _ = to_app.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_a_browser_launch() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(launched_by_browser(&args(&[
            "blackboxus.exe",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
            "--parent-window=0"
        ])));
        assert!(!launched_by_browser(&args(&["blackboxus.exe"])));
        assert!(!launched_by_browser(&args(&["chrome-extension://x/"])));
    }
}
