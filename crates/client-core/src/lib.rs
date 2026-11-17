//! Client logic shared by every BlackBoxus app.
//!
//! Each flow is written without I/O: it returns the [`Request`] to send and
//! takes the [`Response`] that came back. An app sends requests with
//! whatever HTTP client its platform offers, and stores what the flows
//! return in its platform's secure storage. All cryptography comes from
//! `vault-core`; this crate only sequences it and checks every answer the
//! server gives.
//!
//! - [`signup`]: create an account and its Emergency Kit (spec section 3).
//! - [`login`]: sign in and unlock the key set (spec sections 3.8 and 4).
//! - [`keys`]: look up other accounts' keys through key transparency
//!   (spec section 9).
//! - [`enrolment`]: add a device by QR code (spec section 10.3).
//! - [`password`]: change the master password (spec section 3.9).
//! - [`recovery`]: set up a recovery key, and recover an account with it
//!   (spec section 11).
//! - [`vaults`]: create, sync, edit and share vaults, keeping a verified,
//!   encrypted local copy (spec sections 6–8).

mod error;
mod http;

pub mod enrolment;
pub mod keys;
pub mod login;
pub mod password;
pub mod recovery;
pub mod signup;
pub mod vaults;

pub use error::{ClientError, Result};
pub use http::{Method, Request, Response, Session};
