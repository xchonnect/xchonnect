#!/usr/bin/env bash
# Generate the three scenario files from processes.pvl.txt and run ProVerif on them.
# Usage: ./gen.sh [run]   (run requires `proverif` on PATH or the xchonnect-proverif:local image)
set -euo pipefail
cd "$(dirname "$0")"
P=$(cat processes.pvl.txt)

queries_common='
query attacker(secretD2W).
query attacker(secretW2D).
query r: key; inj-event(DappActive(r)) ==> inj-event(WalletActive(r)).
query r: key, hu: bitstring, e: G, ct: bitstring; event(WalletActive(r)) ==> event(DappAccepted(hu, e, ct, r)).
query hu: bitstring, e: G, ct: bitstring, r: key; event(WalletReplied(hu, e, ct, r)) ==> event(DappIssued(hu)).
query hu: bitstring, e: G, ct: bitstring, r: key; event(DappAccepted(hu, e, ct, r)) ==> event(WalletReplied(hu, e, ct, r)).
'

# 1. Base: QR private, relay/network attacker, origin key secret.
{ echo "${P//LEAK_QR/}"; echo "$queries_common";
  echo 'process new sko: sskey; out(c, spk(sko)); ( (!Dapp(sko)) | (!Wallet(spk(sko))) )'; } > pairing_base.pv

# 2. QR leak: the attacker also sees the QR (shoulder surfing / screen capture).
{ echo "${P//LEAK_QR/out(c, (mbxP, dpk, s, sign(sigin, sko)));}"; echo "$queries_common";
  echo 'process new sko: sskey; out(c, spk(sko)); ( (!Dapp(sko)) | (!Wallet(spk(sko))) )'; } > pairing_qr_leak.pv

# 3. Origin key leaked after the sessions (forward secrecy w.r.t. the only long-term key).
{ echo "${P//LEAK_QR/}"; echo "$queries_common";
  echo 'process new sko: sskey; out(c, spk(sko)); ( (!Dapp(sko)) | (!Wallet(spk(sko))) | (phase 1; out(c, sko)) )'; } > pairing_origin_key_leak.pv

if [ "${1:-}" = run ]; then
  for f in pairing_base pairing_qr_leak pairing_origin_key_leak; do
    echo "===== $f"
    if command -v proverif >/dev/null; then
      proverif -lib xchonnect "$f.pv" | grep -E "^RESULT"
    else
      docker run --rm -v "$PWD:/m" -w /m xchonnect-proverif:local bash -lc "eval \$(opam env) && proverif -lib xchonnect $f.pv" | grep -E "^RESULT"
    fi
  done
fi
