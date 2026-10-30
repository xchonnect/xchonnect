//! The wallet's checks of a `chia_fundChannel` request (wallet-kit `fund_channel.rs`, spec
//! 9.1 "Channel funding") on agent-chosen params, and the bech32m address decoder.
//!
//! Input: the params' JSON text (lossy UTF-8). Seeds are the vectors' requests, written by
//! the `fund_channel_fuzz_seeds` test in `crates/wallet-kit`. The wallet owns every puzzle
//! hash, so the fuzzer reaches the address check. Each input is checked as it is, and again
//! with its listing re-signed by a fixed operator key (its `operator_pk` set to that key), so
//! fuzzer-built networks, timeouts and hex reach checks 3 to 6 past the signature.
#![no_main]

use chia_bls::{SecretKey, sign};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use xchonnect_wallet_kit::fund_channel::{
    MAX_CHANNEL_TIMEOUT, address_prefix, check_fund_channel, decode_address, encode_address,
    listing_message,
};
use xchonnect_wallet_kit::policy::Network;

/// Between the vectors' `issued` and `expires`.
const NOW: u64 = 1_800_000_001;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `params` with its listing's `operator_pk` set to a fixed key and signed by it.
fn resigned(params: &str) -> Option<String> {
    let mut p: Value = serde_json::from_str(params).ok()?;
    let mut listing: Value = serde_json::from_str(p.get("listing")?.get("listing")?.as_str()?).ok()?;
    let sk = SecretKey::from_seed(&[9; 32]);
    *listing.as_object_mut()?.entry("operator_pk").or_insert(Value::Null) = hex(&sk.public_key().to_bytes()).into();
    let text = listing.to_string();
    let signature = hex(&sign(&sk, listing_message(&text)).to_bytes());
    *p.get_mut("listing")? = serde_json::json!({ "listing": text, "signature": signature });
    Some(p.to_string())
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Some((prefix, ph)) = decode_address(&text) {
        // A decoded address encodes back to itself, in lower case.
        assert_eq!(encode_address(&prefix, &ph), text.to_ascii_lowercase());
    }
    let inputs = [Some(text.to_string()), resigned(&text)];
    for (text, network) in inputs.iter().flatten().flat_map(|t| [(t, Network::Mainnet), (t, Network::Testnet11)]) {
        let Ok(ok) = check_fund_channel(text, &network, NOW, |_| true) else {
            continue;
        };
        // An accepted request pays the address its values make, on this network, and only
        // what the agent asked for.
        assert!(ok.amount > 0);
        assert!(ok.channel.timeout > 0 && ok.channel.timeout <= MAX_CHANNEL_TIMEOUT);
        assert_eq!(ok.listing.network, network.chain_id());
        assert!(ok.listing.expires > NOW);
        assert_eq!(ok.channel.deposit_puzzle_hash(), ok.deposit_puzzle_hash);
        assert_eq!(encode_address(&address_prefix(&network), &ok.deposit_puzzle_hash), ok.address);
        assert_eq!(ok.refund_not_before, NOW + ok.channel.timeout);
    }
});
