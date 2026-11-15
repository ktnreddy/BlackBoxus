//! Starts the BlackBoxus desktop app.

// Release builds on Windows open no console window next to the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> Result<(), blackboxus_desktop::StartError> {
    blackboxus_desktop::run()
}
