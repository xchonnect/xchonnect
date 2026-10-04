//! CHIP-0002 `coinSpends` JSON → `chia_protocol::CoinSpend` (spec 9.1 encodings).

use crate::error::KitError;
use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use serde_json::Value;

/// Maximum spends accepted in one request.
pub const MAX_SPENDS: usize = 500;

fn hex_bytes(v: &Value, what: &'static str) -> Result<Vec<u8>, KitError> {
    let s = v.as_str().ok_or(KitError::InvalidRequest(what))?;
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(s).map_err(|_| KitError::InvalidRequest(what))
}

fn bytes32(v: &Value, what: &'static str) -> Result<Bytes32, KitError> {
    let b: [u8; 32] = hex_bytes(v, what)?
        .try_into()
        .map_err(|_| KitError::InvalidRequest(what))?;
    Ok(Bytes32::from(b))
}

/// Amounts may be JSON numbers or decimal strings (spec 9.1).
fn amount(v: &Value) -> Result<u64, KitError> {
    match v {
        Value::Number(n) => n.as_u64().ok_or(KitError::InvalidRequest("coin.amount")),
        Value::String(s)
            if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse()
                .map_err(|_| KitError::InvalidRequest("coin.amount"))
        }
        _ => Err(KitError::InvalidRequest("coin.amount")),
    }
}

/// Parse the `coinSpends` array of a `signCoinSpends` request.
pub fn parse_coin_spends(coin_spends: &Value) -> Result<Vec<CoinSpend>, KitError> {
    let arr = coin_spends
        .as_array()
        .ok_or(KitError::InvalidRequest("coinSpends"))?;
    if arr.is_empty() || arr.len() > MAX_SPENDS {
        return Err(KitError::InvalidRequest("coinSpends length"));
    }
    arr.iter()
        .map(|cs| {
            let coin = cs.get("coin").ok_or(KitError::InvalidRequest("coin"))?;
            Ok(CoinSpend::new(
                Coin::new(
                    bytes32(
                        coin.get("parent_coin_info").unwrap_or(&Value::Null),
                        "coin.parent_coin_info",
                    )?,
                    bytes32(
                        coin.get("puzzle_hash").unwrap_or(&Value::Null),
                        "coin.puzzle_hash",
                    )?,
                    amount(coin.get("amount").unwrap_or(&Value::Null))?,
                ),
                Program::from(hex_bytes(
                    cs.get("puzzle_reveal").unwrap_or(&Value::Null),
                    "puzzle_reveal",
                )?),
                Program::from(hex_bytes(
                    cs.get("solution").unwrap_or(&Value::Null),
                    "solution",
                )?),
            ))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_both_hex_styles_and_amount_forms() {
        let cs = json!([{
            "coin": { "parent_coin_info": format!("0x{}", "11".repeat(32)), "puzzle_hash": "22".repeat(32), "amount": "18446744073709551615" },
            "puzzle_reveal": "0x80", "solution": "80"
        }]);
        let v = parse_coin_spends(&cs).unwrap();
        assert_eq!(v[0].coin.amount, u64::MAX);
        assert_eq!(v[0].puzzle_reveal.as_ref(), &[0x80]);
        let bad = [
            json!([]),
            json!([{ "coin": { "parent_coin_info": "11", "puzzle_hash": "22".repeat(32), "amount": 1 }, "puzzle_reveal": "80", "solution": "80" }]),
            json!([{ "coin": { "parent_coin_info": "11".repeat(32), "puzzle_hash": "22".repeat(32), "amount": -1 }, "puzzle_reveal": "80", "solution": "80" }]),
            json!([{ "coin": { "parent_coin_info": "11".repeat(32), "puzzle_hash": "22".repeat(32), "amount": "1e3" }, "puzzle_reveal": "80", "solution": "80" }]),
            json!([{ "coin": { "parent_coin_info": "11".repeat(32), "puzzle_hash": "22".repeat(32), "amount": 1 }, "puzzle_reveal": "zz", "solution": "80" }]),
        ];
        for b in bad {
            assert!(parse_coin_spends(&b).is_err(), "{b}");
        }
    }
}
