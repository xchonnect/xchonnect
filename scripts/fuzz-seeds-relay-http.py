#!/usr/bin/env python3
"""Seed corpus for the `relay_http` fuzz target.

The target's input format is documented at the top of fuzz/fuzz_targets/relay_http.rs:

    byte  n                       -> n % 6 + 1 requests follow
    per request:
      byte  route                 -> index into ROUTES
      byte  method                -> index into METHODS
      byte  flags                 -> bit0 real mailbox id, bit1 real read token,
                                     bit2 real write token, bit3 API key header,
                                     bit4 content-type: application/json
      u16be len || bytes          -> capability token (raw, base64-encoded by the target)
      u16be len || bytes          -> path parameter
      u16be len || bytes          -> query string
      u16be len || bytes          -> body

These seeds are the well-formed requests of the relay API, so libFuzzer starts from
inputs that reach the handlers instead of 404s. Regenerate with:

    ./scripts/fuzz-seeds-relay-http.py            # writes fuzz/corpus/relay_http/
    ./scripts/fuzz-seeds-relay-http.py --check    # fail if the committed seeds differ
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "fuzz" / "corpus" / "relay_http"

# ROUTES / METHODS indices, kept in step with fuzz_targets/relay_http.rs.
HEALTHZ, READYZ, INFO, CHALLENGE, TICKETS, MAILBOXES = 0, 1, 2, 3, 4, 5
MAILBOX, MESSAGES, ACK, PUSH, METRICS, OHTTP = 6, 7, 8, 9, 10, 11
GET, POST, PUT, DELETE = 0, 1, 2, 3

REAL_ID, REAL_READ, REAL_WRITE, API_KEY, JSON_CT = 1, 2, 4, 8, 16

# token_hash("xchonnect v1 token" || token) of the fuzz target's fixed tokens is computed
# by the target itself; a seed only has to say "use the real one".
READ_HASH_PLACEHOLDER = base64.b64encode(b"\x00" * 32).decode()


def chunk(b: bytes) -> bytes:
    if len(b) > 0xFFFF:
        raise ValueError("chunk too long")
    return len(b).to_bytes(2, "big") + b


def request(route: int, method: int, flags: int, *, token=b"", path=b"", query=b"", body=b"") -> bytes:
    return (
        bytes([route, method, flags])
        + chunk(token)
        + chunk(path)
        + chunk(query)
        + chunk(body)
    )


def seed(*requests: bytes) -> bytes:
    return bytes([len(requests)]) + b"".join(requests)


def envelope_b64() -> str:
    """A real envelope, reused from the envelope_decode seed corpus."""
    raw = (ROOT / "fuzz" / "corpus" / "envelope_decode" / "seed-session").read_bytes()
    return base64.b64encode(raw).decode()


def seeds() -> dict[str, bytes]:
    j = lambda obj: json.dumps(obj, separators=(",", ":")).encode()
    create_body = j(
        {
            "read_token_hash": READ_HASH_PLACEHOLDER,
            "write_token_hash": base64.b64encode(b"\x01" * 32).decode(),
        }
    )
    return {
        "seed-health": seed(
            request(HEALTHZ, GET, 0),
            request(READYZ, GET, 0),
            request(INFO, GET, 0),
        ),
        "seed-create": seed(
            request(MAILBOXES, POST, JSON_CT, body=create_body),
            request(CHALLENGE, POST, JSON_CT, body=b"{}"),
        ),
        "seed-post-message": seed(
            request(
                MESSAGES,
                POST,
                REAL_ID | REAL_WRITE | JSON_CT,
                body=j({"env": envelope_b64(), "ttl_s": 3600}),
            ),
        ),
        "seed-fetch-ack": seed(
            request(MESSAGES, GET, REAL_ID | REAL_READ, query=b"limit=8&wait=0"),
            request(
                ACK,
                POST,
                REAL_ID | REAL_READ | JSON_CT,
                body=j({"msg_ids": [base64.b64encode(b"\x02" * 16).decode()]}),
            ),
        ),
        "seed-push-delete": seed(
            request(PUSH, PUT, REAL_ID | REAL_READ | JSON_CT, body=j({"push_reg": None})),
            request(MAILBOX, DELETE, REAL_ID | REAL_WRITE),
        ),
        "seed-api-key-create": seed(
            request(MAILBOXES, POST, API_KEY | JSON_CT, body=create_body),
            request(TICKETS, POST, API_KEY | JSON_CT, body=b"{}"),
        ),
        "seed-wrong-token": seed(
            request(MESSAGES, GET, REAL_ID, token=b"\x09" * 32, query=b"wait=0"),
            request(MESSAGES, GET, 0, path=b"not-a-mailbox-id", query=b"wait=0"),
        ),
        "seed-metrics-ohttp": seed(
            request(METRICS, GET, 0),
            request(OHTTP, POST, 0, body=b"\x00\x01\x02\x03"),
        ),
    }


def main() -> int:
    check = "--check" in sys.argv[1:]
    OUT.mkdir(parents=True, exist_ok=True)
    bad = []
    for name, data in seeds().items():
        path = OUT / name
        if check:
            if not path.exists() or path.read_bytes() != data:
                bad.append(name)
        else:
            path.write_bytes(data)
    if check and bad:
        print("stale or missing relay_http seeds: " + ", ".join(bad), file=sys.stderr)
        return 1
    print(("checked " if check else "wrote ") + f"{len(seeds())} seeds in {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
