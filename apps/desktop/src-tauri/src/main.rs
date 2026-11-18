//! Starts the BlackBoxus desktop app.

// Release builds on Windows open no console window next to the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> Result<(), blackboxus_desktop::StartError> {
    // Started by a browser as its native messaging host: relay, nothing else.
    #[cfg(desktop)]
    let args: Vec<String> = std::env::args().collect();
    #[cfg(desktop)]
    if blackboxus_desktop::browser::host::launched_by_browser(&args) {
        blackboxus_desktop::browser::host::relay();
        return Ok(());
    }
    blackboxus_desktop::run()
}
