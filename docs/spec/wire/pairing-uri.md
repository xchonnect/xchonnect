# Pairing URI (normative)

## Grammar (ABNF, RFC 5234)

```abnf
pairing-uri   = "xchonnect:v1?" params
universal-uri = "https://" link-host link-path "#" params   ; e.g. https://klimper.app/pair#...
params        = param *( "&" param )
param         = key "=" value
key           = 1*ALPHA
value         = *( unreserved / pct-encoded )               ; RFC 3986
```

Parameters may appear in any order; each MUST appear at most once; unknown parameters
MUST be ignored. In the universal-link form the parameters MUST be in the fragment so
they are never sent to a web server.

| Key | Required | Value | Decoded |
|---|---|---|---|
| `r` | yes | percent-encoded relay base URL | absolute `https` URL, no query/fragment, no trailing `/`, at most 200 bytes. Wallets MAY accept `http` for loopback hosts in an explicit developer mode only. |
| `m` | yes | base64url | 16-byte pairing mailbox id `mbx_P` |
| `w` | yes | base64url | 32-byte write token `wP` |
| `k` | yes | base64url | 32-byte X25519 public key `dpk` |
| `s` | yes | base64url | 32-byte pairing secret |
| `d` | yes | domain | lowercase A-label host name (punycode), at most 253 bytes, no scheme, no port. In developer mode wallets MAY accept `localhost:<port>`. |
| `x` | yes | decimal | expiry, unix seconds; MUST be at most 300 s after the time the URI is created |
| `i` | yes | `1*64( ALPHA / DIGIT / "." / "_" / "-" )` | origin key id `kid` |
| `o` | yes | base64url | 64-byte Ed25519 signature |
| `t` | no | base64url | 32-byte sponsorship ticket (spec 7.5) |

All binary values are base64url **without padding** (RFC 4648 §5). Decoders MUST reject
padding characters, non-canonical base64url (non-zero trailing bits) and wrong lengths.

## Signature input

```
uri_sig_input = canonical_cbor([ "xchonnect pairing uri v1", r, mbx_P, wP, dpk, d, x, kid ])
o             = Ed25519-Sign(origin_sk, uri_sig_input)
h_uri         = SHA-256(uri_sig_input)
```

Array elements: `r`, `d`, `kid` as text strings exactly as decoded above; `mbx_P`, `wP`,
`dpk` as byte strings; `x` as unsigned integer. The pairing secret `s` and ticket `t` are
**not** signed, so the origin-signing service (HSM/KMS) never sees the pairing secret.

## Wallet verification order

1. Parse; reject on any grammar or length error.
2. Reject if `x` is in the past, or more than 300 s (+ 60 s clock skew) in the future.
3. Fetch the origin document for `d` (`xchonnect.schema.json`), select `kid`, reject if
   missing or past `not_after`.
4. Verify `o` over `uri_sig_input` (strict Ed25519 verification: reject non-canonical
   `S` and small-order public keys).
5. Display the verified domain and ask the user.

## Length budget

With a 40-byte relay URL and 15-byte domain the URI is about 360 characters, which fits
a QR code of version 14 at error-correction level M.
