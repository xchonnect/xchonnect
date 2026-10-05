//! The optional CHIP-0002 methods (spec 9.1): `getAssetCoins`, `getAssetBalance`,
//! `filterUnlockedCoins`, `sendTransaction` and `walletSwitchChain`.
//!
//! The first four need the wallet's view of the chain, which this crate does not have. The
//! host supplies it through [`ChainData`]; this module parses and bounds the params, scopes
//! every query to the dApp's grant, and shapes the CHIP-0002 result, so each wallet does
//! not have to. A wallet without chain data passes no [`ChainData`] and these methods stay
//! `4004 method not found`, as before.
//!
//! **Scope.** A dApp only ever learns about coins controlled by the public keys exposed to
//! it (`DappPermissions::exposed_keys`), which it could read from the chain itself. Every
//! query carries those keys, and a host must not answer for any other coin.

use crate::handlers::RpcError;
use crate::spend::{decode_hex, parse_coin_spends};
use chia_bls::{PublicKey, Signature};
use chia_protocol::{Bytes32, Coin, Program, SpendBundle};
use serde_json::{Value, json};
use xchonnect_core::rpc::codes;

/// Most coins one `getAssetCoins` page returns.
pub const MAX_COIN_PAGE: u32 = 100;
/// `getAssetCoins` page size when the dApp gives none (Sage's WalletConnect default).
pub const DEFAULT_COIN_PAGE: u32 = 10;
/// Most coin ids one `filterUnlockedCoins` request may ask about.
pub const MAX_FILTER_COINS: usize = 500;

/// Which asset a read is about (CHIP-0002 `type` and `assetId`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    /// `type: null`: the native asset.
    Xch,
    /// `type: "cat"` with its asset id (TAIL hash); a CAT read always names one.
    Cat(Bytes32),
    /// `type: "did"`, one launcher id or every DID.
    Did(Option<Bytes32>),
    /// `type: "nft"`, one launcher id or every NFT.
    Nft(Option<Bytes32>),
}

/// A `getAssetCoins` query, already bounded.
#[derive(Debug, Clone)]
pub struct CoinQuery<'a> {
    /// The asset.
    pub asset: AssetKind,
    /// Include coins that are locked (pending in a transaction or an offer).
    pub include_locked: bool,
    /// Coins to skip.
    pub offset: u32,
    /// Coins to return, at most [`MAX_COIN_PAGE`].
    pub limit: u32,
    /// Only coins controlled by these keys may be returned.
    pub keys: &'a [PublicKey],
}

/// CHIP-0002 `lineageProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageProof {
    /// Parent coin id.
    pub parent_name: Bytes32,
    /// The parent's inner puzzle hash; `None` for an eve proof.
    pub inner_puzzle_hash: Option<Bytes32>,
    /// The parent's amount.
    pub amount: u64,
}

/// One entry of a `getAssetCoins` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendableCoin {
    /// The coin.
    pub coin: Coin,
    /// Its full puzzle reveal (outer layers included).
    pub puzzle: Program,
    /// Height of the block that created it.
    pub confirmed_block_index: u32,
    /// Pending in a transaction or an offer.
    pub locked: bool,
    /// For CATs, DIDs and NFTs.
    pub lineage_proof: Option<LineageProof>,
}

/// A `getAssetBalance` result. Sums are `u128`: the total XCH supply in mojos exceeds
/// `u64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AssetBalance {
    /// Every coin, locked or not.
    pub confirmed: u128,
    /// Coins not locked.
    pub spendable: u128,
    /// Number of coins not locked.
    pub spendable_coin_count: u32,
}

/// What a node said about a broadcast spend bundle (CHIP-0002 `MempoolInclusionStatus`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStatus {
    /// 1 success, 2 pending, 3 failed.
    pub status: u8,
    /// The node's error, if it refused the bundle.
    pub error: Option<String>,
}

/// Why the host could not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// This wallet does not offer the method; answered with `4004`.
    Unsupported,
    /// The wallet cannot reach its data right now (not synced, no peers, locked).
    Unavailable,
}

/// The wallet's view of the chain. Every method has a default that returns
/// [`ChainError::Unsupported`], so a host implements only what it offers.
///
/// Calls run inline in [`crate::handle`], like [`crate::Signer`]: a host whose data is
/// async blocks on it here.
pub trait ChainData {
    /// Coins of `query.asset` controlled by `query.keys`, in an order that is stable
    /// between calls, so consecutive pages neither overlap nor skip.
    fn asset_coins(&self, _query: &CoinQuery<'_>) -> Result<Vec<SpendableCoin>, ChainError> {
        Err(ChainError::Unsupported)
    }

    /// Balance of `asset` over the coins controlled by `keys`.
    fn asset_balance(
        &self,
        _asset: AssetKind,
        _keys: &[PublicKey],
    ) -> Result<AssetBalance, ChainError> {
        Err(ChainError::Unsupported)
    }

    /// The subset of `coin_ids` that are controlled by `keys` and not locked.
    fn unlocked_coins(
        &self,
        _coin_ids: &[Bytes32],
        _keys: &[PublicKey],
    ) -> Result<Vec<Bytes32>, ChainError> {
        Err(ChainError::Unsupported)
    }

    /// Broadcast an already signed spend bundle.
    fn send_transaction(&self, _bundle: &SpendBundle) -> Result<TxStatus, ChainError> {
        Err(ChainError::Unsupported)
    }
}

fn invalid(what: &str) -> RpcError {
    RpcError {
        code: codes::INVALID_PARAMS,
        message: "invalid params".to_owned(),
        data: Some(json!({ "reason": what }).to_string()),
    }
}

impl From<ChainError> for RpcError {
    fn from(e: ChainError) -> Self {
        match e {
            ChainError::Unsupported => RpcError {
                code: codes::METHOD_NOT_FOUND,
                message: "method not found".to_owned(),
                data: None,
            },
            // CHIP-0002 has no code for this; 4000 with a reason, so a dApp can retry.
            ChainError::Unavailable => RpcError {
                code: codes::INVALID_PARAMS,
                message: "the wallet cannot read the chain right now".to_owned(),
                data: Some(json!({ "reason": "unavailable" }).to_string()),
            },
        }
    }
}

fn hex32(v: &Value) -> Option<Bytes32> {
    let b: [u8; 32] = v.as_str().and_then(decode_hex)?.try_into().ok()?;
    Some(Bytes32::from(b))
}

fn hex(bytes: &[u8]) -> String {
    format!("0x{}", ::hex::encode(bytes))
}

/// Amounts above 2^53 − 1 are strings (spec 9.1); smaller ones stay numbers, which every
/// CHIP-0002 client already reads.
fn amount_json(v: u64) -> Value {
    if v < (1 << 53) {
        json!(v)
    } else {
        json!(v.to_string())
    }
}

/// CHIP-0002 `type` + `assetId` → [`AssetKind`].
fn asset_kind(params: &Value) -> Result<AssetKind, RpcError> {
    let id = match params.get("assetId") {
        None | Some(Value::Null) => None,
        Some(v) => Some(hex32(v).ok_or_else(|| invalid("assetId"))?),
    };
    match params.get("type") {
        None | Some(Value::Null) => match id {
            None => Ok(AssetKind::Xch),
            Some(_) => Err(invalid("assetId")),
        },
        Some(Value::String(t)) => match t.as_str() {
            "cat" => id.map(AssetKind::Cat).ok_or_else(|| invalid("assetId")),
            "did" => Ok(AssetKind::Did(id)),
            "nft" => Ok(AssetKind::Nft(id)),
            _ => Err(invalid("type")),
        },
        Some(_) => Err(invalid("type")),
    }
}

fn page(params: &Value, key: &str, default: u32) -> Result<u32, RpcError> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| invalid(key)),
    }
}

pub(crate) fn get_asset_coins(
    params: &Value,
    keys: &[PublicKey],
    chain: &dyn ChainData,
) -> Result<String, RpcError> {
    let query = CoinQuery {
        asset: asset_kind(params)?,
        include_locked: params
            .get("includedLocked")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        offset: page(params, "offset", 0)?,
        limit: page(params, "limit", DEFAULT_COIN_PAGE)?.min(MAX_COIN_PAGE),
        keys,
    };
    let coins = chain.asset_coins(&query)?;
    let out: Vec<Value> = coins
        .iter()
        .take(query.limit as usize)
        .map(|c| {
            json!({
                "coin": {
                    "parent_coin_info": hex(c.coin.parent_coin_info.as_ref()),
                    "puzzle_hash": hex(c.coin.puzzle_hash.as_ref()),
                    "amount": amount_json(c.coin.amount),
                },
                "coinName": hex(c.coin.coin_id().as_ref()),
                "puzzle": hex(c.puzzle.as_ref()),
                "confirmedBlockIndex": c.confirmed_block_index,
                "locked": c.locked,
                "lineageProof": c.lineage_proof.as_ref().map(|p| json!({
                    "parentName": hex(p.parent_name.as_ref()),
                    "innerPuzzleHash": p.inner_puzzle_hash.map(|h| hex(h.as_ref())),
                    "amount": amount_json(p.amount),
                })),
            })
        })
        .collect();
    Ok(Value::Array(out).to_string())
}

pub(crate) fn get_asset_balance(
    params: &Value,
    keys: &[PublicKey],
    chain: &dyn ChainData,
) -> Result<String, RpcError> {
    let b = chain.asset_balance(asset_kind(params)?, keys)?;
    // Strings: balances are sums and regularly exceed 2^53.
    Ok(json!({
        "confirmed": b.confirmed.to_string(),
        "spendable": b.spendable.to_string(),
        "spendableCoinCount": b.spendable_coin_count,
    })
    .to_string())
}

pub(crate) fn filter_unlocked_coins(
    params: &Value,
    keys: &[PublicKey],
    chain: &dyn ChainData,
) -> Result<String, RpcError> {
    let names = params
        .get("coinNames")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty() && a.len() <= MAX_FILTER_COINS)
        .ok_or_else(|| invalid("coinNames"))?;
    let ids = names
        .iter()
        .map(|v| hex32(v).ok_or_else(|| invalid("coinNames")))
        .collect::<Result<Vec<_>, _>>()?;
    let unlocked = chain.unlocked_coins(&ids, keys)?;
    // Only ids the dApp asked about, in its order: a host can add nothing.
    let out: Vec<String> = ids
        .iter()
        .filter(|id| unlocked.contains(id))
        .map(|id| hex(id.as_ref()))
        .collect();
    Ok(json!(out).to_string())
}

pub(crate) fn send_transaction(params: &Value, chain: &dyn ChainData) -> Result<String, RpcError> {
    let bundle = params
        .get("spendBundle")
        .ok_or_else(|| invalid("spendBundle"))?;
    let spends = parse_coin_spends(bundle.get("coin_spends").unwrap_or(&Value::Null))
        .map_err(|_| invalid("spendBundle.coin_spends"))?;
    let sig: [u8; 96] = bundle
        .get("aggregated_signature")
        .and_then(Value::as_str)
        .and_then(decode_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("spendBundle.aggregated_signature"))?;
    let sig =
        Signature::from_bytes(&sig).map_err(|_| invalid("spendBundle.aggregated_signature"))?;
    let status = chain.send_transaction(&SpendBundle::new(spends, sig))?;
    Ok(json!({ "status": status.status, "error": status.error }).to_string())
}

/// The session is bound to the chain it was paired on (spec 9.3), so this only confirms
/// that chain; switching would be a new pairing.
pub(crate) fn wallet_switch_chain(params: &Value, chain_id: &str) -> Result<String, RpcError> {
    let wanted = params
        .get("chainId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("chainId"))?;
    if wanted.strip_prefix("chia:").unwrap_or(wanted) == chain_id {
        Ok("true".to_owned())
    } else {
        Err(RpcError {
            code: codes::UNAUTHORIZED,
            message: "unauthorized".to_owned(),
            data: Some(json!({ "reason": "wrong_network" }).to_string()),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::handlers::{Approver, Prompt, RequestContext, Signer, SignerError, handle};
    use crate::permissions::{DEFAULT_METHODS, DappPermissions, OPTIONAL_METHODS};
    use crate::policy::Network;
    use crate::simulate::Ownership;
    use crate::swap_fixture::Mem;
    use chia_sdk_test::BlsPair;
    use std::cell::RefCell;
    use std::collections::HashSet;

    struct NoSigner;
    impl Signer for NoSigner {
        fn sign(&self, _: &PublicKey, _: &[u8]) -> Result<Signature, SignerError> {
            Err(SignerError::KeyUnavailable)
        }
    }
    struct NoUi;
    impl Approver for NoUi {
        fn approve(&self, _: &Prompt<'_>) -> bool {
            false
        }
    }

    /// Answers from fixed data and records every query, so a test can see what the host
    /// was asked and with which keys.
    #[derive(Default)]
    struct Fake {
        coins: Vec<SpendableCoin>,
        balance: AssetBalance,
        unlocked: Vec<Bytes32>,
        status: Option<TxStatus>,
        down: bool,
        asked: RefCell<Vec<String>>,
        keys_seen: RefCell<Vec<Vec<PublicKey>>>,
        sent: RefCell<Vec<SpendBundle>>,
    }
    impl ChainData for Fake {
        fn asset_coins(&self, q: &CoinQuery<'_>) -> Result<Vec<SpendableCoin>, ChainError> {
            self.asked.borrow_mut().push(format!(
                "coins {:?} locked={} offset={} limit={}",
                q.asset, q.include_locked, q.offset, q.limit
            ));
            self.keys_seen.borrow_mut().push(q.keys.to_vec());
            if self.down {
                return Err(ChainError::Unavailable);
            }
            Ok(self.coins.clone())
        }
        fn asset_balance(
            &self,
            asset: AssetKind,
            keys: &[PublicKey],
        ) -> Result<AssetBalance, ChainError> {
            self.asked.borrow_mut().push(format!("balance {asset:?}"));
            self.keys_seen.borrow_mut().push(keys.to_vec());
            Ok(self.balance)
        }
        fn unlocked_coins(
            &self,
            _ids: &[Bytes32],
            keys: &[PublicKey],
        ) -> Result<Vec<Bytes32>, ChainError> {
            self.keys_seen.borrow_mut().push(keys.to_vec());
            Ok(self.unlocked.clone())
        }
        fn send_transaction(&self, bundle: &SpendBundle) -> Result<TxStatus, ChainError> {
            self.sent.borrow_mut().push(bundle.clone());
            self.status.clone().ok_or(ChainError::Unsupported)
        }
    }

    fn perms(methods: &[&str]) -> DappPermissions {
        DappPermissions {
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            exposed_keys: vec![BlsPair::new(1).pk, BlsPair::new(2).pk],
            limits: Default::default(),
        }
    }

    fn all() -> DappPermissions {
        perms(&[&DEFAULT_METHODS[..], &OPTIONAL_METHODS[..]].concat())
    }

    fn call(
        perms: &DappPermissions,
        chain: Option<&dyn ChainData>,
        method: &str,
        params: &str,
    ) -> Result<Value, RpcError> {
        let (own, keys, limits) = (Ownership::default(), HashSet::new(), Mem::default());
        let ctx = RequestContext {
            dapp: "dapp.example",
            network: Network::Testnet11,
            session_chain_id: "testnet11",
            permissions: perms,
            allow_agg_sig_unsafe: false,
            allow_unknown_contracts: false,
            ownership: &own,
            keys: &keys,
            limits: &limits,
            now: 1_790_000_000,
            chain,
        };
        handle(method, params, &ctx, &NoSigner, &NoUi).map(|s| serde_json::from_str(&s).unwrap())
    }

    fn b32(n: u8) -> Bytes32 {
        Bytes32::new([n; 32])
    }

    fn coin(amount: u64) -> SpendableCoin {
        SpendableCoin {
            coin: Coin::new(b32(1), b32(2), amount),
            puzzle: Program::from(vec![0x01]),
            confirmed_block_index: 7,
            locked: false,
            lineage_proof: Some(LineageProof {
                parent_name: b32(3),
                inner_puzzle_hash: None,
                amount: 5,
            }),
        }
    }

    const XCH: &str = r#"{"type":null,"assetId":null}"#;

    #[test]
    fn without_chain_data_or_without_the_grant_the_methods_are_not_found() {
        let fake = Fake::default();
        for m in [
            "getAssetCoins",
            "getAssetBalance",
            "filterUnlockedCoins",
            "sendTransaction",
        ] {
            let no_chain = call(&all(), None, m, XCH).unwrap_err();
            assert_eq!(
                no_chain.code,
                codes::METHOD_NOT_FOUND,
                "{m} without chain data"
            );
            let not_granted = call(&perms(&DEFAULT_METHODS), Some(&fake), m, XCH).unwrap_err();
            assert_eq!(not_granted.code, codes::METHOD_NOT_FOUND, "{m} not granted");
        }
        assert!(fake.asked.borrow().is_empty(), "nothing reached the host");
    }

    #[test]
    fn every_read_is_scoped_to_the_keys_exposed_to_the_dapp() {
        let fake = Fake {
            unlocked: vec![b32(9)],
            ..Fake::default()
        };
        let p = all();
        call(&p, Some(&fake), "getAssetCoins", XCH).unwrap();
        call(&p, Some(&fake), "getAssetBalance", XCH).unwrap();
        let ids = format!(r#"{{"coinNames":["{}"]}}"#, hex(b32(9).as_ref()));
        call(&p, Some(&fake), "filterUnlockedCoins", &ids).unwrap();
        let seen = fake.keys_seen.borrow();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|k| *k == p.exposed_keys));
    }

    #[test]
    fn get_asset_coins_parses_bounds_and_shapes_the_page() {
        let mut coins: Vec<SpendableCoin> = (0..150).map(|_| coin(1)).collect();
        coins[0] = coin(1 << 60); // above 2^53: must be a string
        let fake = Fake {
            coins,
            ..Fake::default()
        };
        let cat = hex(b32(4).as_ref());
        let params = format!(
            r#"{{"type":"cat","assetId":"{cat}","includedLocked":true,"offset":3,"limit":1000}}"#
        );
        let out = call(&all(), Some(&fake), "getAssetCoins", &params).unwrap();
        assert_eq!(
            fake.asked.borrow()[0],
            format!("coins Cat({}) locked=true offset=3 limit=100", b32(4))
        );
        let page = out.as_array().unwrap();
        assert_eq!(
            page.len(),
            100,
            "a host that returns too much is cut to the page"
        );
        assert_eq!(page[0]["coin"]["amount"], json!((1u64 << 60).to_string()));
        assert_eq!(page[1]["coin"]["amount"], json!(1));
        assert_eq!(
            page[1]["coinName"],
            json!(hex(coin(1).coin.coin_id().as_ref()))
        );
        assert_eq!(page[1]["puzzle"], json!("0x01"));
        assert_eq!(page[1]["confirmedBlockIndex"], json!(7));
        assert_eq!(
            page[1]["lineageProof"]["parentName"],
            json!(hex(b32(3).as_ref()))
        );
        assert_eq!(page[1]["lineageProof"]["innerPuzzleHash"], Value::Null);

        call(&all(), Some(&fake), "getAssetCoins", XCH).unwrap();
        assert_eq!(
            fake.asked.borrow()[1],
            "coins Xch locked=false offset=0 limit=10"
        );
    }

    #[test]
    fn asset_params_are_validated() {
        let fake = Fake::default();
        for bad in [
            r#"{"type":"cat","assetId":null}"#,
            r#"{"type":"token","assetId":null}"#,
            r#"{"type":null,"assetId":"0x1234"}"#,
            r#"{"type":"nft","assetId":"0xzz"}"#,
            r#"{"type":null,"assetId":null,"limit":-1}"#,
        ] {
            let e = call(&all(), Some(&fake), "getAssetCoins", bad).unwrap_err();
            assert_eq!(e.code, codes::INVALID_PARAMS, "{bad}");
        }
        assert!(fake.asked.borrow().is_empty());
    }

    #[test]
    fn balances_are_strings_and_may_exceed_u64() {
        let fake = Fake {
            balance: AssetBalance {
                confirmed: u128::from(u64::MAX) + 1,
                spendable: 10,
                spendable_coin_count: 2,
            },
            ..Fake::default()
        };
        let out = call(&all(), Some(&fake), "getAssetBalance", r#"{"type":"did"}"#).unwrap();
        assert_eq!(
            out,
            json!({
                "confirmed": "18446744073709551616",
                "spendable": "10",
                "spendableCoinCount": 2,
            })
        );
        assert_eq!(fake.asked.borrow()[0], "balance Did(None)");
    }

    #[test]
    fn filter_unlocked_coins_returns_only_ids_the_dapp_asked_about_in_its_order() {
        let fake = Fake {
            // The host also returns an id nobody asked about; it must not leak.
            unlocked: vec![b32(8), b32(6), b32(7)],
            ..Fake::default()
        };
        let ask = [b32(6), b32(5), b32(8)].map(|b| hex(b.as_ref()));
        let out = call(
            &all(),
            Some(&fake),
            "filterUnlockedCoins",
            &json!({ "coinNames": ask }).to_string(),
        )
        .unwrap();
        assert_eq!(out, json!([ask[0], ask[2]]));

        for bad in [json!({ "coinNames": [] }), json!({ "coinNames": ["0x12"] })] {
            let e = call(&all(), Some(&fake), "filterUnlockedCoins", &bad.to_string());
            assert_eq!(e.unwrap_err().code, codes::INVALID_PARAMS, "{bad}");
        }
        let too_many = json!({ "coinNames": vec![hex(b32(1).as_ref()); MAX_FILTER_COINS + 1] });
        let e = call(
            &all(),
            Some(&fake),
            "filterUnlockedCoins",
            &too_many.to_string(),
        );
        assert_eq!(e.unwrap_err().code, codes::INVALID_PARAMS);
    }

    #[test]
    fn send_transaction_hands_the_parsed_bundle_to_the_host() {
        let fake = Fake {
            status: Some(TxStatus {
                status: 3,
                error: Some("DOUBLE_SPEND".to_owned()),
            }),
            ..Fake::default()
        };
        let sig = hex(&Signature::default().to_bytes());
        let spend = json!({
            "coin": { "parent_coin_info": hex(b32(1).as_ref()), "puzzle_hash": hex(b32(2).as_ref()), "amount": "5" },
            "puzzle_reveal": "0x01",
            "solution": "0x80",
        });
        let params =
            json!({ "spendBundle": { "coin_spends": [spend], "aggregated_signature": sig } });
        let out = call(&all(), Some(&fake), "sendTransaction", &params.to_string()).unwrap();
        assert_eq!(out, json!({ "status": 3, "error": "DOUBLE_SPEND" }));
        let sent = fake.sent.borrow();
        assert_eq!(sent[0].coin_spends[0].coin.amount, 5);

        let bad =
            json!({ "spendBundle": { "coin_spends": [spend], "aggregated_signature": "0x00" } });
        let e = call(&all(), Some(&fake), "sendTransaction", &bad.to_string()).unwrap_err();
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(sent.len(), 1, "an invalid bundle never reaches the host");
    }

    #[test]
    fn an_unavailable_host_is_a_retryable_error_not_a_missing_method() {
        let fake = Fake {
            down: true,
            ..Fake::default()
        };
        let e = call(&all(), Some(&fake), "getAssetCoins", XCH).unwrap_err();
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(e.data.as_deref(), Some(r#"{"reason":"unavailable"}"#));
    }

    #[test]
    fn wallet_switch_chain_confirms_the_session_chain_and_refuses_any_other() {
        let p = all();
        for same in [
            r#"{"chainId":"testnet11"}"#,
            r#"{"chainId":"chia:testnet11"}"#,
        ] {
            assert_eq!(
                call(&p, None, "walletSwitchChain", same).unwrap(),
                json!(true)
            );
        }
        let e = call(&p, None, "walletSwitchChain", r#"{"chainId":"mainnet"}"#).unwrap_err();
        assert_eq!(e.code, codes::UNAUTHORIZED);
        assert_eq!(e.data.as_deref(), Some(r#"{"reason":"wrong_network"}"#));
        let not_granted = call(&perms(&DEFAULT_METHODS), None, "walletSwitchChain", "{}");
        assert_eq!(not_granted.unwrap_err().code, codes::METHOD_NOT_FOUND);
    }
}
