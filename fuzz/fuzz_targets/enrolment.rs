//! Enrolment transfers (spec section 10.3): the encrypted transfer from the
//! server, and the payload inside it.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::device::EnrolmentOffer;
use vault_core::fuzzing::{decode_enrolment_payload, encode_enrolment_payload};

fuzz_target!(|data: &[u8]| {
    if let Ok(payload) = decode_enrolment_payload(data) {
        let once = encode_enrolment_payload(&payload).expect("re-encodes");
        let twice = encode_enrolment_payload(&decode_enrolment_payload(&once).expect("re-decodes"))
            .expect("re-encodes");
        assert_eq!(once.as_slice(), twice.as_slice());
    }
    let offer = EnrolmentOffer::from_qr_text(
        "blackboxus-enrol:1:000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
    )
    .expect("fixed offer");
    assert!(offer.open(data).is_err(), "forged transfer opened");
});
