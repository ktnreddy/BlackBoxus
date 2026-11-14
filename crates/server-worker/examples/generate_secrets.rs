//! Generates the server's secrets for a new deployment.
//!
//! Writes them as JSON (for `wrangler secret bulk`) to the file given as the
//! only argument, which must not exist yet, and prints the public half of
//! the key transparency log key, which clients must have built in.
//!
//! Run once per deployment, never again: new secrets would invalidate every
//! account's login and every client's trust in the key log. The deploy
//! workflow runs this only when the Worker has no secrets at all.

#![allow(clippy::print_stdout, reason = "command-line tool")]

use std::fs::OpenOptions;
use std::io::Write as _;

use server_core::login::OpaqueServer;
use server_worker::http::{b64, hex};
use vault_core::IdentitySecretKey;
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: generate_secrets <output.json>")?;

    let mut fake_salt_key = Zeroizing::new([0_u8; 32]);
    getrandom_04::fill(fake_salt_key.as_mut_slice()).map_err(|_| "random generator failed")?;
    let log_key = IdentitySecretKey::generate()?;

    let json = Zeroizing::new(format!(
        "{{\"OPAQUE_SETUP\":\"{}\",\"FAKE_SALT_KEY\":\"{}\",\"LOG_SIGNING_KEY\":\"{}\"}}",
        b64(&OpaqueServer::generate().to_bytes()),
        b64(fake_salt_key.as_slice()),
        b64(log_key.to_seed_bytes().as_slice()),
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(json.as_bytes())?;

    let public = log_key.public_key().to_bytes();
    println!("Key transparency log public key (build this into the clients):");
    println!("{}", hex(&public));
    Ok(())
}
