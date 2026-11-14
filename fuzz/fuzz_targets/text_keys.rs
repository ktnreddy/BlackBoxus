//! Secret Keys, recovery keys and enrolment QR codes typed or scanned by
//! the user (spec sections 3.2, 10.3, 11.2).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::SecretKey;
use vault_core::device::EnrolmentOffer;
use vault_core::recovery::RecoveryKey;

fuzz_target!(|text: &str| {
    if let Ok(key) = SecretKey::parse(text) {
        let shown = key.to_display_string();
        assert_eq!(
            SecretKey::parse(&shown)
                .expect("re-parses")
                .to_display_string()
                .as_str(),
            shown.as_str()
        );
    }
    if let Ok(key) = RecoveryKey::parse(text) {
        let shown = key.to_display_string();
        assert_eq!(
            RecoveryKey::parse(&shown)
                .expect("re-parses")
                .to_display_string()
                .as_str(),
            shown.as_str()
        );
    }
    if let Ok(offer) = EnrolmentOffer::from_qr_text(text) {
        let qr = offer.to_qr_text();
        assert_eq!(
            EnrolmentOffer::from_qr_text(&qr)
                .expect("re-parses")
                .to_qr_text()
                .as_str(),
            qr.as_str()
        );
    }
});
