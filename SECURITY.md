# Security policy

Xchonnect carries signing requests for real funds. We take every report seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://github.com/maximedogawa/xchonnect/security/advisories/new)
("Report a vulnerability" on the Security tab).

Please include the affected component (core, relay, gateway, wallet-kit, SDK, spec),
version or commit, impact, and reproduction steps. Reports about the **specification**
(protocol design flaws) are in scope and as welcome as implementation bugs.

If GitHub is unavailable to you, say so in a public issue **without any detail about the
issue itself** and ask for a private channel.

### Downstream projects

Findings in the Xchonnect libraries (`xchonnect-core`, `xchonnect-wallet-kit`, the
bindings, `@maximedogawa/xchonnect`, the reference relay and gateway) belong here, even when they
surface in a product that embeds them. Projects that depend on Xchonnect are asked to
forward such findings to this process rather than patch locally, so every integrator gets
the fix. We will coordinate the embargo with you and credit you in the advisory.

If a finding is in the wallet engine a product is built on rather than in Xchonnect, it
belongs with that project; say which you think it is and we will redirect rather than
drop it.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment and severity | within 10 working days |
| Fix or mitigation for critical/high issues | as fast as possible, normally within 30 days |
| Public advisory | coordinated with the reporter after a fix is available; user-facing disclosure within 72 hours of confirming active exploitation (spec Section 16) |

We credit reporters in the advisory unless they prefer otherwise.

Our side of the process — private fix, coordinated release, advisory, and the operator
runbooks for key compromise, relay compromise, a leaked sealed push token and malicious
updates — is written out in
[docs/guides/incident-response.md](docs/guides/incident-response.md).

## Scope

In scope, in this repository:

- `crates/core` — envelopes, canonical CBOR, the pairing handshake and key schedule,
  session state and replay protection.
- `crates/relay` — the reference relay, including the OHTTP gateway, mailbox tokens, rate
  limits, TTLs, proof-of-work, sponsorship tickets and wake-up egress rules.
- `crates/gateway` — the reference push gateway: sealed token handling, expiry, per-device
  rate limiting.
- `crates/wallet-kit` — spend simulation, the signature policy, multi-party binding checks,
  permissions and limits.
- `bindings/wasm`, `bindings/uniffi`, `sdk-ts` — the published API surfaces, including
  anything that leaks secrets across an FFI or WASM boundary.
- `docs/spec/**` — the specification itself, the wire formats and the test vectors.
- The build and release pipeline: dependency integrity, CI configuration, anything in
  `.github/`.

What we especially want to hear about: a way for the relay to read or forge a message; a
pairing that completes without domain verification or the SAS comparison; a partial
signature produced for an unbound multi-party spend; a signature produced without
simulation or approval; the relay learning an IP, address, public key or device token;
non-constant-time comparison of anything authenticating; a panic or unbounded allocation on
attacker-controlled input.

### Out of scope

- Missing hardening with no demonstrated impact, results from automated scanners without
  a working proof, and best-practice opinions about TLS configuration or HTTP headers on
  hosts we do not operate.
- Denial of service that only requires sending lots of traffic. Resource exhaustion that
  defeats a **documented bound** (a rate limit, a size limit, a TTL, the proof-of-work)
  with modest resources is in scope.
- Social engineering of maintainers or users, physical attacks, and anything requiring a
  jailbroken or already-compromised device.
- Third-party relays, gateways and wallets are operated by their owners; report issues in
  their deployments to them. Issues in the *protocol* that make those deployments unsafe
  are ours.
- Known limitations listed in spec Section 13.6 and in
  [docs/guides/security-and-privacy.md](docs/guides/security-and-privacy.md) are not
  vulnerabilities by themselves — but a report showing one is **worse than documented** is
  in scope and valuable.
- The hosted relay product (relayxch/nodexch), the Klimper wallet apps and the Pengui dApp
  live in other repositories with their own contacts.

## Safe harbour

If you make a good-faith effort to follow this policy, we will not pursue or support legal
action against you for your research, and we will treat your activity as authorised under
applicable anti-hacking law and our terms. Good faith means:

- You use only your **own** accounts, devices, keys and test funds, or those of someone who
  consented. Do not touch another person's sessions, mailboxes or funds.
- You test against a relay you run yourself, or against a testnet deployment. The local
  stack is one command (`./scripts/dev.sh`) — use it in preference to anyone's production
  relay.
- You do not degrade service for others: no volumetric denial of service, no spam, no
  mass mailbox creation against a relay you do not operate.
- You do not access, modify, exfiltrate or retain data that is not yours. If you encounter
  someone else's data, stop, do not save it, and tell us what you saw.
- You report promptly, give us a reasonable time to fix (see the targets above), and keep
  the finding private until the advisory is out or we agree otherwise.
- You do not use the finding for extortion and do not require payment as a condition of
  disclosure.

This is our commitment, not legal advice, and it cannot bind third parties: if you test
against someone else's relay, gateway or wallet, their rules apply and we cannot protect
you. Nothing here authorises touching a hosted production deployment.

## Bug bounty

**There is no cash bounty programme yet.** A public bounty is planned before the mainnet
release (spec Section 16; backlog TASK-65), and the scope and safe harbour above are
written to be the scope of that programme when it opens. Until it does, we offer credit in
the advisory and in a hall of fame, not money. We would rather say this plainly than let
you spend a weekend expecting a payout.

The reward scale on launch is intended to follow impact, with the highest band reserved for
anything that breaks a security invariant in spec Section 13.4 — key exposure, the relay
reading or forging messages, a signature without approval, or an unbound partial signature.

## Supported versions

Xchonnect is pre-1.0. Only the latest commit on `main` and the latest release receive
security fixes. Do not use pre-1.0 releases to protect mainnet funds without your own
review.

**No external security audit has been completed.** See
[docs/guides/security-and-privacy.md](docs/guides/security-and-privacy.md) for what that
means and for the other known limitations.
