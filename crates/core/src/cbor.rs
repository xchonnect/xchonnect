//! Strict canonical CBOR (spec Section 5.4).
//!
//! Only the data model the protocol needs is supported: unsigned and negative
//! integers, byte strings, text strings, arrays, maps, booleans and null. The encoder
//! always produces the core deterministic encoding (RFC 8949 §4.2.1) with map keys
//! sorted by their encoded bytes; the decoder rejects every input that is not exactly
//! that encoding, so each value has a single valid byte representation.

use crate::error::{Error, Result};

/// Maximum nesting depth of arrays and maps.
pub const MAX_DEPTH: usize = 16;
/// Maximum number of entries in one array or map.
pub const MAX_ITEMS: usize = 1024;

/// A CBOR value restricted to the canonical profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 1; the value is `-1 - n`.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3 (valid UTF-8).
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5. Order is irrelevant on input; encoding sorts canonically.
    Map(Vec<(Value, Value)>),
    /// `false` / `true`.
    Bool(bool),
    /// `null`.
    Null,
}

impl Value {
    /// Text value from `&str`.
    pub fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    /// Byte-string value from a slice.
    pub fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    /// Signed integer.
    pub fn int(i: i64) -> Value {
        if i >= 0 {
            Value::Uint(i.unsigned_abs())
        } else {
            Value::Nint(i.unsigned_abs() - 1)
        }
    }

    /// Map with text keys.
    pub fn text_map(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::text(k), v))
                .collect(),
        )
    }

    /// The value as `u64`, if it is an unsigned integer.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(u) => Some(*u),
            _ => None,
        }
    }

    /// The value as `i64`, if it is an integer in range.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Uint(u) => i64::try_from(*u).ok(),
            Value::Nint(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    /// The value as a byte slice.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The value as `&str`.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The value as an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The value as `bool`.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Look up a text key in a map.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.find(|k| k.as_text() == Some(key))
    }

    /// Look up an unsigned-integer key in a map.
    pub fn get_uint(&self, key: u64) -> Option<&Value> {
        self.find(|k| k.as_u64() == Some(key))
    }

    fn find(&self, key: impl Fn(&Value) -> bool) -> Option<&Value> {
        let Value::Map(m) = self else { return None };
        m.iter().find(|(k, _)| key(k)).map(|(_, v)| v)
    }

    /// The map entry `key` converted with `conv`, or `Error::Malformed(err)` if it is
    /// missing or has the wrong type.
    pub(crate) fn field<'a, T>(
        &'a self,
        key: &str,
        err: &'static str,
        conv: impl FnOnce(&'a Value) -> Option<T>,
    ) -> Result<T> {
        self.get(key).and_then(conv).ok_or(Error::Malformed(err))
    }

    /// Whether this is a map.
    pub fn is_map(&self) -> bool {
        matches!(self, Value::Map(_))
    }
}

// --- Encoding ------------------------------------------------------------------------------

fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u64::from(u8::MAX) {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Uint(u) => write_head(out, 0, *u),
        Value::Nint(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            write_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(a) => {
            write_head(out, 4, a.len() as u64);
            for item in a {
                encode_into(item, out)?;
            }
        }
        Value::Map(m) => {
            let mut entries = Vec::with_capacity(m.len());
            for (k, val) in m {
                let mut kb = Vec::new();
                encode_into(k, &mut kb)?;
                entries.push((kb, val));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            if entries
                .windows(2)
                .any(|w| matches!(w, [a, b] if a.0 == b.0))
            {
                return Err(Error::Cbor("duplicate map key"));
            }
            write_head(out, 5, entries.len() as u64);
            for (kb, val) in entries {
                out.extend_from_slice(&kb);
                encode_into(val, out)?;
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
    Ok(())
}

/// Encode canonically. Fails only on duplicate map keys.
pub fn encode(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(v, &mut out)?;
    Ok(out)
}

// --- Decoding ------------------------------------------------------------------------------

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Cbor("length overflow"))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(Error::Cbor("unexpected end"))?;
        self.pos = end;
        Ok(s)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Cbor("unexpected end"))
    }

    fn byte(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(Error::Cbor("unexpected end"))
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Read a head and return (major, argument), enforcing shortest form.
    fn head(&mut self) -> Result<(u8, u64)> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major == 7 {
            return Ok((7, u64::from(ai)));
        }
        // Each argument width must be needed: `min` is the smallest value it may carry.
        let (n, min) = match ai {
            0..=23 => (u64::from(ai), 0),
            24 => (u64::from(self.byte()?), 24),
            25 => (u64::from(u16::from_be_bytes(self.take_array()?)), 1 << 8),
            26 => (u64::from(u32::from_be_bytes(self.take_array()?)), 1 << 16),
            27 => (u64::from_be_bytes(self.take_array()?), 1 << 32),
            31 => return Err(Error::Cbor("indefinite length")),
            _ => return Err(Error::Cbor("reserved additional info")),
        };
        if n < min {
            return Err(Error::Cbor("non-shortest integer"));
        }
        Ok((major, n))
    }

    fn len(&self, n: u64) -> Result<usize> {
        let n = usize::try_from(n).map_err(|_| Error::Cbor("length overflow"))?;
        if n > self.remaining() {
            return Err(Error::Cbor("length exceeds input"));
        }
        Ok(n)
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        let (major, n) = self.head()?;
        match major {
            0 => Ok(Value::Uint(n)),
            1 => Ok(Value::Nint(n)),
            2 => Ok(Value::Bytes(self.take(self.len(n)?)?.to_vec())),
            3 => {
                let s = core::str::from_utf8(self.take(self.len(n)?)?);
                Ok(Value::Text(
                    s.map_err(|_| Error::Cbor("invalid UTF-8"))?.to_owned(),
                ))
            }
            4 => {
                if depth >= MAX_DEPTH {
                    return Err(Error::Cbor("nesting too deep"));
                }
                // Every item takes at least one byte.
                let count = self.len(n)?;
                if count > MAX_ITEMS {
                    return Err(Error::Cbor("too many items"));
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                if depth >= MAX_DEPTH {
                    return Err(Error::Cbor("nesting too deep"));
                }
                let count = usize::try_from(n).map_err(|_| Error::Cbor("length overflow"))?;
                if count > MAX_ITEMS || count.saturating_mul(2) > self.remaining() {
                    return Err(Error::Cbor("too many items"));
                }
                let mut entries = Vec::with_capacity(count);
                let mut prev_key: Option<&[u8]> = None;
                for _ in 0..count {
                    let start = self.pos;
                    let k = self.value(depth + 1)?;
                    let kbytes = self
                        .buf
                        .get(start..self.pos)
                        .ok_or(Error::Cbor("unexpected end"))?;
                    if let Some(p) = prev_key {
                        if kbytes <= p {
                            return Err(Error::Cbor(
                                "map keys not in canonical order or duplicated",
                            ));
                        }
                    }
                    prev_key = Some(kbytes);
                    let v = self.value(depth + 1)?;
                    entries.push((k, v));
                }
                Ok(Value::Map(entries))
            }
            6 => Err(Error::Cbor("tags are not allowed")),
            _ => match n {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(Error::Cbor("simple value or float not allowed")),
            },
        }
    }
}

/// Decode exactly one canonical item; trailing bytes are an error.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let (v, used) = decode_prefix(bytes)?;
    if used != bytes.len() {
        return Err(Error::Cbor("trailing bytes"));
    }
    Ok(v)
}

/// Decode one canonical item from the start of `bytes`; returns it and the bytes used.
pub fn decode_prefix(bytes: &[u8]) -> Result<(Value, usize)> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    let v = d.value(0)?;
    Ok((v, d.pos))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn rfc8949_examples_roundtrip() {
        let cases = [
            (Value::Uint(0), "00"),
            (Value::Uint(23), "17"),
            (Value::Uint(24), "1818"),
            (Value::Uint(1000), "1903e8"),
            (Value::Uint(1_000_000), "1a000f4240"),
            (Value::Uint(1_000_000_000_000), "1b000000e8d4a51000"),
            (Value::int(-1), "20"),
            (Value::int(-1000), "3903e7"),
            (Value::Bytes(vec![1, 2, 3, 4]), "4401020304"),
            (Value::text("IETF"), "6449455446"),
            (Value::text("\u{00fc}"), "62c3bc"),
            (Value::Array(vec![Value::Uint(1), Value::Uint(2)]), "820102"),
            (Value::Bool(false), "f4"),
            (Value::Null, "f6"),
        ];
        for (v, h) in cases {
            assert_eq!(hex::encode(encode(&v).unwrap()), h);
            assert_eq!(decode(&hx(h)).unwrap(), v);
        }
    }

    #[test]
    fn map_keys_sorted_by_encoding() {
        // Shorter encodings sort first: 10 (0x0a) < 100 (0x1864) < -1 (0x20) < "z" < "aa"
        let v = Value::Map(vec![
            (Value::text("aa"), Value::Null),
            (Value::text("z"), Value::Null),
            (Value::int(-1), Value::Null),
            (Value::Uint(100), Value::Null),
            (Value::Uint(10), Value::Null),
        ]);
        assert_eq!(
            hex::encode(encode(&v).unwrap()),
            "a50af61864f620f6617af6626161f6"
        );
    }

    #[test]
    fn rejects_non_canonical() {
        let bad = [
            ("1817", "non-shortest 1-byte"),
            ("190017", "non-shortest 2-byte"),
            ("1a0000ffff", "non-shortest 4-byte"),
            ("1b00000000ffffffff", "non-shortest 8-byte"),
            ("5f4101ff", "indefinite bytes"),
            ("9f01ff", "indefinite array"),
            ("c11a514b67b0", "tag"),
            ("f93c00", "half float"),
            ("fb3ff0000000000000", "double"),
            ("f7", "undefined"),
            ("f0", "simple value"),
            ("a2616201616101", "unsorted keys"),
            ("a2616101616102", "duplicate keys"),
            ("62c328", "invalid utf-8"),
            ("0000", "trailing byte"),
            ("1c", "reserved ai"),
            ("5a00ffffff", "length beyond input"),
            ("9bffffffffffffffff", "huge array"),
        ];
        for (h, why) in bad {
            assert!(decode(&hx(h)).is_err(), "{why} must be rejected");
        }
    }

    #[test]
    fn depth_and_item_limits() {
        let mut v = Value::Null;
        for _ in 0..MAX_DEPTH {
            v = Value::Array(vec![v]);
        }
        assert!(decode(&encode(&v).unwrap()).is_ok());
        let v = Value::Array(vec![v]);
        assert_eq!(
            decode(&encode(&v).unwrap()),
            Err(Error::Cbor("nesting too deep"))
        );

        let big = Value::Array(vec![Value::Null; MAX_ITEMS + 1]);
        assert_eq!(
            decode(&encode(&big).unwrap()),
            Err(Error::Cbor("too many items"))
        );
    }

    #[test]
    fn encoder_rejects_duplicate_keys() {
        let v = Value::text_map(vec![("a", Value::Null), ("a", Value::Null)]);
        assert!(encode(&v).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod prop {
        use super::super::*;
        use proptest::prelude::*;

        fn arb_value() -> impl Strategy<Value = Value> {
            let leaf = prop_oneof![
                any::<u64>().prop_map(Value::Uint),
                any::<u64>().prop_map(Value::Nint),
                proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
                ".{0,20}".prop_map(Value::Text),
                any::<bool>().prop_map(Value::Bool),
                Just(Value::Null),
            ];
            leaf.prop_recursive(4, 64, 8, |inner| {
                prop_oneof![
                    proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                    proptest::collection::btree_map(".{0,6}", inner, 0..8).prop_map(
                        |m| Value::Map(m.into_iter().map(|(k, v)| (Value::Text(k), v)).collect())
                    ),
                ]
            })
        }

        proptest! {
            #[test]
            fn roundtrip_is_canonical(v in arb_value()) {
                let bytes = encode(&v).unwrap();
                let back = decode(&bytes).unwrap();
                prop_assert_eq!(encode(&back).unwrap(), bytes);
            }

            #[test]
            fn decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                if let Ok(v) = decode(&bytes) {
                    // Anything accepted must re-encode to the identical bytes.
                    prop_assert_eq!(encode(&v).unwrap(), bytes);
                }
            }
        }
    }
}
