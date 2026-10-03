# Persisted session state (format v1)

`Session::to_bytes()` returns a canonical CBOR map that hosts store **encrypted** (platform
keychain on mobile, IndexedDB with a non-extractable WebCrypto key in browsers; spec 12.1).
It contains secrets. Hosts MUST persist it after every mutating call and before posting
the resulting envelope (spec 5.3 sender state-loss rule).

| Key | Type | Meaning |
|---|---|---|
| `v` | uint | format version, currently `1`; unknown versions are rejected |
| `role` | text | `"dapp"` or `"wallet"` |
| `keys` | map | current epoch: `e` (uint), `d2w`, `w2d`, `ck` (32-byte bstr each) |
| `own_mbx`, `own_r` | bstr | mailbox this side reads and its read token |
| `peer_mbx`, `peer_w` | bstr | peer mailbox and its write token |
| `send_seq`, `recv_seq` | uint | last sent / last accepted `seq` (replay protection) |
| `sas_ok` | bool | the local user confirmed the SAS |
| `peer_ready` | bool | dApp received `session.ready` |
| `ended` | bool | session ended |
| `epoch_started`, `epoch_sent` | uint | rotation threshold bookkeeping |
| `prev` | map, optional | previous epoch being drained: `keys`, `mbx`, `r` |
| `rot` | map, optional | rotation offered by this side: `sk` (X25519 secret), `e`, `mbx`, `r` |

Changes to this format bump `v`; `from_bytes` must keep reading older versions once
any release has shipped.
