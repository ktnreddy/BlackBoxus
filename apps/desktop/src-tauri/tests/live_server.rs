//! Account flows against a running server. Ignored by default; run with a
//! local server (see docs/deployment.md):
//!
//! ```sh
//! BLACKBOXUS_API_URL=http://127.0.0.1:8787 cargo test -p blackboxus-desktop -- --ignored
//! ```

use blackboxus_desktop::AppError;
use blackboxus_desktop::flows::{create_account, sign_in};
use blackboxus_desktop::http::{Https, ORIGIN};
use vault_core::{SecretKey, ServerIdentity};

const PASSWORD: &str = "lantern-orbit-velvet-quarry";

#[test]
#[ignore = "needs a running server"]
fn create_sign_in_and_reject_a_wrong_password() -> Result<(), AppError> {
    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let email = format!("desktop-{nonce}@example.com");

    let (created, secret_key, kit) = create_account(&transport, &server, &email, PASSWORD)?;
    assert_eq!(kit.email, email);
    assert!(SecretKey::parse(&kit.secret_key)? == secret_key);

    let again = sign_in(&transport, &server, &email, &secret_key, PASSWORD)?;
    assert_eq!(again.session.account_id(), created.session.account_id());

    let wrong = sign_in(&transport, &server, &email, &secret_key, "not-the-password");
    assert_eq!(wrong.err(), Some(AppError::WrongCredentials));

    let taken = create_account(&transport, &server, &email, PASSWORD);
    assert_eq!(taken.err(), Some(AppError::EmailTaken));
    Ok(())
}
