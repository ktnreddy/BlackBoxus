//! Whole revision logs as served for a vault (spec section 8.4).
#![no_main]
use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use vault_core::log::verify_log;

fuzz_target!(|entries: Vec<Vec<u8>>| {
    let f = blackboxus_fuzz::fixture();
    let _ = verify_log(&f.vault_id, &entries, &HashMap::new(), None);
});
