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

## Logging and metrics policy (spec 13.5)

- Logs contain only startup/shutdown events and backend error descriptions; there is no
  request logging. Set `XCHONNECT_LOG` (e.g. `warn`) to control verbosity.
- `/metrics` exposes aggregates only: request counts by **route template** and status
  class, latency histograms, and the number of mailboxes. Restrict access to it at the
  reverse proxy, or disable it with `XCHONNECT_METRICS=0`.
- Per-customer usage for billing is available in-process (`AppState::usage()`), never
  per end user.
- Recommended retention for any logs the proxy or platform keeps: at most 14 days.
- A test (`api::privacy_tests`) runs every endpoint at TRACE level and fails if any
  mailbox id, token, token hash, message id or envelope appears in logs or metrics.
