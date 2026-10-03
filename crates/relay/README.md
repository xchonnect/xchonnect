# xchonnect-relay

Reference relay for the Xchonnect protocol: anonymous, capability-token mailboxes that
store end-to-end encrypted envelopes until the recipient fetches them
(spec Section 7, API in `docs/spec/wire/relay-api.md`).

```sh
cargo run -p xchonnect-relay                      # in-memory store on 127.0.0.1:8787
XCHONNECT_DATABASE_URL=postgres://… cargo run -p xchonnect-relay
```

All settings are environment variables; see the table in `src/config.rs`.

## TLS

The relay speaks plain HTTP and must run behind a TLS-terminating reverse proxy (Caddy,
nginx, a load balancer) in production. Clients require `https` relay URLs except in
explicit developer mode. Configure the proxy **not** to log request URLs (they contain
mailbox ids), `Authorization` headers or client IPs beyond what the provider enforces,
and disclose it in your data inventory (spec 10.3, 13.5).

## What the relay never does

- read client IP addresses, `User-Agent` or forwarding headers (enforced by a source test);
- log request paths, tokens, mailbox ids or ciphertext;
- store anything except token hashes, day-granular timestamps, optional sealed push
  registrations, the optional customer id, and ciphertext with its expiry.
