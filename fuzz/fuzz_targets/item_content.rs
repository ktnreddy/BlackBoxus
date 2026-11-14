//! Item content as decrypted from an envelope (spec section 6.3). A vault
//! member holding the key can put any bytes here.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::fuzzing::{decode_item, encode_item, pad_content, unpad_content};

fuzz_target!(|data: &[u8]| {
    if let Ok(item) = decode_item(data) {
        let encoded = encode_item(&item).expect("a decoded item re-encodes");
        assert_eq!(decode_item(&encoded).expect("re-decodes"), item);
    }
    if let Ok(content) = unpad_content(data) {
        let padded = pad_content(&content).expect("unpadded content pads");
        assert_eq!(unpad_content(&padded).expect("unpads"), content);
    }
});
