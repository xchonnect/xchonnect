//! The wallet's checks of a `chia_fundChannel` request (wallet-kit `fund_channel.rs`, spec
//! 9.1 "Channel funding") on agent-chosen params, and the bech32m address decoder.
//!
//! Input: the params' JSON text (lossy UTF-8). Seeds are the vectors' requests, written by
//! the `fund_channel_fuzz_seeds` test in `crates/wallet-kit`. The wallet owns every puzzle
//! hash, so the fuzzer reaches the address check.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xchonnect_wallet_kit::fund_channel::{
    MAX_CHANNEL_TIMEOUT, address_prefix, check_fund_channel, decode_address, encode_address,
};
use xchonnect_wallet_kit::policy::Network;

/// Between the vectors' `issued` and `expires`.
const NOW: u64 = 1_800_000_001;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Some((prefix, ph)) = decode_address(&text) {
        // A decoded address encodes back to itself, in lower case.
        assert_eq!(encode_address(&prefix, &ph), text.to_ascii_lowercase());
    }
    for network in [Network::Mainnet, Network::Testnet11] {
        let Ok(ok) = check_fund_channel(&text, &network, NOW, |_| true) else {
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
