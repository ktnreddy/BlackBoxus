//! HTTP requests arriving at the server (spec section 12).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use server_worker::http::{
    LoginFinishRequest, LoginStartRequest, PreloginRequest, RegisterFinishRequest, b64,
    bearer_token, parse_json, parse_seen, route, unb64,
};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    header: &'a str,
    body: &'a [u8],
}

fuzz_target!(|i: Input<'_>| {
    let _ = route(i.method, i.path);
    let _ = parse_seen(Some(i.query));
    let _ = bearer_token(Some(i.header));
    let _ = parse_json::<PreloginRequest>(i.body);
    let _ = parse_json::<LoginStartRequest>(i.body);
    let _ = parse_json::<LoginFinishRequest>(i.body);
    let _ = parse_json::<RegisterFinishRequest>(i.body);
    if let Ok(bytes) = unb64(i.query, 4096) {
        assert_eq!(b64(&bytes), i.query, "base64url must be canonical");
    }
});
