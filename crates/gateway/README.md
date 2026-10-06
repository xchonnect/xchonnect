# xchonnect-gateway

> [!WARNING]
> **Pre-audit pre-release: testnet only, no real funds.** Xchonnect has not had an
> external security audit. Do not use any 0.x release to move, sign for or protect mainnet
> funds. Report vulnerabilities privately:
> [SECURITY.md](https://github.com/xchonnect/xchonnect/blob/main/SECURITY.md).

Reference push gateway for the Xchonnect protocol (spec 7.3, 7.3.2). Each wallet vendor
runs its own instance with its own APNs/FCM credentials, so no shared push service learns
who is being woken.

For every wake-up it opens the sealed push token with its own key, rate-limits per device
in memory, hands the token to the platform sender, and forgets it. It never sees mailbox
ids or message content, never writes device tokens to disk or logs, and answers every
request identically so that it cannot be used as an oracle for whether a token is valid.

```sh
cargo run -p xchonnect-gateway          # 127.0.0.1:8788
```

Configuration is environment variables; the table lives in `src/main.rs`. Deployment,
including the container image, is in
[`deploy/`](https://github.com/xchonnect/xchonnect/tree/main/deploy) and
[`docs/operating.md`](https://github.com/xchonnect/xchonnect/blob/main/docs/operating.md).

As a library, implement the `Sender` trait to plug in a platform other than APNs or FCM.

## Licence and security

Apache-2.0 ([`LICENSE`](https://github.com/xchonnect/xchonnect/blob/main/LICENSE)).

Report vulnerabilities privately — **not** as a public issue — per
[`SECURITY.md`](https://github.com/xchonnect/xchonnect/blob/main/SECURITY.md).
Pre-audit software: review it yourself before running it for real users.
