# Security policy

Xchonnect carries signing requests for real funds. We take every report seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://github.com/maximedogawa/xchonnect/security/advisories/new)
("Report a vulnerability" on the Security tab).

Please include the affected component (core, relay, gateway, wallet-kit, SDK, spec),
version or commit, impact, and reproduction steps. Reports about the **specification**
(protocol design flaws) are in scope and as welcome as implementation bugs.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment and severity | within 10 working days |
| Fix or mitigation for critical/high issues | as fast as possible, normally within 30 days |
| Public advisory | coordinated with the reporter after a fix is available; user-facing disclosure within 72 hours of confirming active exploitation (spec Section 16) |

We credit reporters in the advisory unless they prefer otherwise. A bug bounty programme
will be announced before the mainnet release (TASK-65).

## Supported versions

Xchonnect is pre-1.0. Only the latest commit on `main` and the latest release receive
security fixes. Do not use pre-1.0 releases to protect mainnet funds without your own
review.

## Scope notes

- Known limitations listed in spec Section 13.6 are not vulnerabilities by themselves,
  but reports showing they are worse than documented are in scope.
- Third-party relays, gateways and wallets are operated by their owners; report issues
  in their deployments to them.
