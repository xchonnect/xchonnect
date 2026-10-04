# Symbolic model of the pairing handshake (ProVerif)

Model of spec 5.2 and 6.3 in the Dolev–Yao setting: the network **and the relay** are the
attacker (A3, A4), with unbounded parallel sessions of dApps and wallets sharing one origin
key. Primitives are ideal: X25519 as a DH group with the usual equation, Ed25519 as a
signature scheme, HPKE `mode_psk` as a key schedule over (DH secret, PSK, info) with an AEAD
and an exporter, HKDF/SHA-256 as one-way functions.

```sh
./gen.sh          # regenerate the scenario files from processes.pvl.txt
./gen.sh run      # run ProVerif (local `proverif` or the xchonnect-proverif:local image)
```

A Docker image can be built with
`docker run ocaml/opam:debian-12-ocaml-5.2 bash -c "opam install -y proverif"` and
`docker commit`. Results below: ProVerif 2.05, 2026-10-04.

## Scenarios

| File | Attacker additionally has |
|---|---|
| `pairing_base.pv` | — (QR shown privately to the user's wallet) |
| `pairing_qr_leak.pv` | the full QR code incl. the pairing secret `s` (shoulder surfing, screen capture) |
| `pairing_origin_key_leak.pv` | the origin signing key, after the sessions (phase 1) |

## Results

| Property (query) | base | qr_leak | origin_key_leak |
|---|---|---|---|
| Secrecy of dApp→wallet and wallet→dApp messages after pairing | true | true | true (forward secrecy w.r.t. the origin key) |
| dApp active ⇒ a wallet is active with the same root (injective agreement) | true | true | true |
| wallet active ⇒ a dApp accepted its exact reply (same root) | true | true | true |
| wallet replied ⇒ the dApp issued that URI (origin authentication) | true | true | true |
| dApp accepted a reply ⇒ an honest wallet sent exactly it (transcript agreement at acceptance) | true | **cannot be proved** | true |

The one failing query is expected: with the QR code, an attacker can win the race and get
its own reply accepted (spec 6.3 step 5). The model confirms that this never leads to an
active dApp session with the attacker, because activation requires the user's SAS
confirmation on the dApp (`in(user, =sas(root))`), and that the honest wallet never becomes
active either (it never receives a `session.confirm` it can open). This is the reason the
spec requires SAS confirmation on **both** devices (spec 6.3 step 8, threat T3).

## What the model does not cover (stated limitations)

- **SAS guessing:** symbolic models treat the SAS as a perfect hash. A real attacker who
  wins the QR race has a 1 in 10^6 chance per attempt that the codes coincide; the pairing
  URI is single-use and short-lived, so each QR gives at most one attempt.
- **Relayed genuine QR (phishing proxy):** a phishing page that shows the real dApp's live
  QR code makes the victim pair with the real dApp under the attacker's dApp account. The
  model's QR channel is private, so this is out of scope; spec 13.4.1 item 6 documents it.
- **Rotation, replay windows, expiry and mailbox handling** are not modelled; they are
  covered by unit, property, fuzz and interop tests.
- **Implementation correctness** (side channels, parser bugs) is out of scope of any
  symbolic model.
