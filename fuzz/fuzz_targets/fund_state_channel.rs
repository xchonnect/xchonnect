//! The wallet's checks of a `chia_fundStateChannel` request (wallet-kit
//! `fund_state_channel.rs`, spec 9.1 "State channel funding") on requester-chosen params, and
//! the step-2 conditions the wallet would sign.
//!
//! Input: the params' JSON text (lossy UTF-8). Seeds are the vectors' requests, written by the
//! `fund_state_channel_fuzz_seeds` test in `crates/wallet-kit`. The wallet owns every puzzle
//! hash. Each input is checked as it is, and again with its listing re-signed by a fixed
//! operator key (its `operator_pk` set to that key, `expires` ahead), so fuzzer-built
//! networks, terms and offers reach the checks past the signature.
#![no_main]

use chia_bls::{SecretKey, sign};
use chia_protocol::{Bytes32, Coin};
use clvm_traits::FromClvm;
use clvmr::{Allocator, NodePtr};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use xchonnect_wallet_kit::fund_state_channel::{check_fund_state_channel, listing_message};
use xchonnect_wallet_kit::policy::Network;

const NOW: u64 = 1_800_000_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `params` with its listing's `operator_pk` set to a fixed key, unexpired, and signed by it.
fn resigned(params: &str) -> Option<String> {
    let mut p: Value = serde_json::from_str(params).ok()?;
    let mut listing: Value = serde_json::from_str(p.get("listing")?.get("listing")?.as_str()?).ok()?;
    let sk = SecretKey::from_seed(&[9; 32]);
    let l = listing.as_object_mut()?;
    l.insert("operator_pk".into(), hex(&sk.public_key().to_bytes()).into());
    l.insert("expires".into(), (NOW + 1).into());
    let text = listing.to_string();
    let signature = hex(&sign(&sk, listing_message(&text)).to_bytes());
    *p.get_mut("listing")? = serde_json::json!({ "listing": text, "signature": signature });
    Some(p.to_string())
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let inputs = [Some(text.to_string()), resigned(&text)];
    for (text, network) in inputs.iter().flatten().flat_map(|t| [(t, Network::Mainnet), (t, Network::Testnet11)]) {
        let Ok(ok) = check_fund_state_channel(text, &network, NOW, |_| true) else {
            continue;
        };
        assert!(ok.amount > 0 && ok.total == ok.amount + ok.fee);
        assert_eq!(ok.listing.network, network.chain_id());
        assert!(ok.listing.expires > NOW && ok.listing.payment.asset == "xch");
        let Some(offer) = &ok.offer else { continue };
        assert_eq!((offer.amount, offer.fee), (ok.total, ok.fee));
        // Step 2 against its own step 1, on a coin of that id holding 7 more: the first coin
        // gets the total, the wallet the 7, every other coin 0, and nothing is signed for.
        let Some(held) = ok.total.checked_add(7) else { continue };
        let mut p: Value = serde_json::from_str(text).unwrap();
        let coin = Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), held);
        p["offer"]["coinId"] = format!("0x{}", hex(&coin.coin_id())).into();
        let two = check_fund_state_channel(&p.to_string(), &network, NOW, |_| true).unwrap();
        p.as_object_mut().unwrap().remove("offer");
        let kept = check_fund_state_channel(&p.to_string(), &network, NOW, |_| true).unwrap();
        let mut a = Allocator::new();
        let change = Bytes32::new([3; 32]);
        let list = two.conditions(&kept, &coin, change, &mut a).unwrap();
        let mut amounts = Vec::new();
        for (opcode, rest) in Vec::<(u32, NodePtr)>::from_clvm(&a, list).unwrap() {
            assert!(!(43..=50).contains(&opcode), "no AGG_SIG");
            if opcode == 51 {
                let (ph, (amount, ())) = <(Bytes32, (u64, ()))>::from_clvm(&a, rest).unwrap();
                assert!(amount == 0 || amounts.is_empty() || (ph == change && amount == 7));
                amounts.push(amount);
            }
        }
        assert_eq!(amounts.first(), Some(&ok.total));
        assert_eq!(amounts.iter().sum::<u64>(), held);
    }
});
