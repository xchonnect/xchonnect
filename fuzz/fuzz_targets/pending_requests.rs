//! Restoring the dApp's pending-request tracker from host storage.
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic)]

use libfuzzer_sys::fuzz_target;
use xchonnect_core::message::Message;
use xchonnect_core::rpc::PendingRequests;

fuzz_target!(|data: &[u8]| {
    let Ok(mut p) = PendingRequests::from_bytes(data) else {
        return;
    };
    // A restored tracker obeys the same invariants as one built with `insert`.
    let items = p.items().to_vec();
    assert!(
        items.len() <= PendingRequests::MAX,
        "too many pending requests restored"
    );
    for (i, a) in items.iter().enumerate() {
        assert!(
            items.iter().skip(i + 1).all(|b| b.id != a.id),
            "duplicate request id restored"
        );
    }
    let bytes = p.to_bytes().unwrap();
    assert_eq!(
        PendingRequests::from_bytes(&bytes).unwrap(),
        p,
        "round trip"
    );

    // Correlation still works on the restored state.
    if let Some(first) = items.first() {
        let id = first.id;
        assert!(p.resolve(&Message::RpcReceived { request_id: id }).is_ok());
        let resp = xchonnect_core::rpc::result(id, "1").unwrap();
        assert!(p.resolve(&resp).is_ok());
        assert!(p.resolve(&resp).is_err(), "answered twice");
    }
    let _ = p.expire(u64::MAX);
    assert!(p.items().iter().all(|x| x.exp == u64::MAX));
});
