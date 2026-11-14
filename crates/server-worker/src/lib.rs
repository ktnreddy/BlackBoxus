//! The BlackBoxus server on Cloudflare Workers (spec section 12).
//!
//! All security checks live in `server-core`. This crate only connects them
//! to HTTP and to Cloudflare's D1 database:
//!
//! - [`http`] holds everything that does not depend on Cloudflare (routing,
//!   JSON, encodings, errors, rate limit keys) and is tested natively;
//! - the `worker` module, built only for WebAssembly, handles requests and
//!   storage.

pub mod http;

#[cfg(target_arch = "wasm32")]
mod worker;
