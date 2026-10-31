# @xchonnect/mcp

The Xchonnect MCP plugin: lets an AI agent (Claude Code first) pair with your Chia wallet and
ask it to trade. The agent talks to the wallet over an Xchonnect session, end to end encrypted
through a relay; **the wallet keeps the keys and the rules you set for the agent**. The plugin
holds neither and builds no spend: it asks the wallet (`chia_takeOffer`, `chia_createOffer`,
`chia_cancelOffer`), and the wallet decodes the request, checks it against your rules, and asks
you or answers within them.

For market data (the offer book, prices, the loan board) add the nodexch MCP server next to it;
the two never share anything but what the agent passes between them.

## Install in Claude Code

```sh
claude mcp add xchonnect -- npx -y @xchonnect/mcp
```

Node.js 22.12 or later. Then, in a chat: "pair my wallet". The plugin opens the pairing QR code
as an image and Claude shows it as text too; scan it with the wallet, and compare the 6-digit
code with the one the wallet shows. Claude Code asks you that question itself (MCP
elicitation), so the answer is yours, not the model's; only then is the session used. It lasts
across chats and restarts until the wallet ends it. One Claude Code session at a time holds it:
a second one says so (give it its own `XCHONNECT_MCP_DIR` to pair it on its own).

The wallet must check the pairing code's origin (spec 6.1), so the plugin needs one of:

- **nodexch** (the simplest): `NODEXCH_KEY=nxs_…`, your agent's secret nodexch API key. nodexch
  signs each pairing as its own domain (nodexch.com) on its relay, and the wallet shows that
  domain. nodexch signs only a pairing on its relay and domain that expires within minutes; it
  never sees the pairing secret, the session or a request. `NODEXCH_URL` must be https (http only
  on the loopback), and the plugin checks at start that the domain publishes the key nodexch
  signs with. `NODEXCH_KEY` is not used when `XCHONNECT_ORIGIN_DOMAIN` or `XCHONNECT_DEV` is set.

  ```sh
  claude mcp add xchonnect -e NODEXCH_KEY=nxs_your_secret_key -- npx -y @xchonnect/mcp
  ```

- **Your own domain:** `XCHONNECT_ORIGIN_DOMAIN=agent.example.org` (and optionally
  `XCHONNECT_ORIGIN_KID`), and the document from the `origin_document` tool served at
  `https://agent.example.org/.well-known/xchonnect.json`.
- **Developer mode:** `XCHONNECT_DEV=1`. The plugin serves the document itself on
  `http://localhost:8797` and uses `http://127.0.0.1:8787` as the relay unless
  `XCHONNECT_RELAY` says otherwise. Only wallets in developer mode accept it; never for funds.

```sh
claude mcp add xchonnect -e XCHONNECT_DEV=1 -- npx -y @xchonnect/mcp
```

Without nodexch and without a domain of your own, pairing an agent (named by you at pairing,
checked by the code alone) is not in the protocol yet; see the limitations below.

## Tools

| Tool | What it does |
| --- | --- |
| `pair` | Starts pairing: the QR code as an image (opened) and as text, and the pairing string |
| `pairing_status` | Waits for the wallet to scan; returns the 6-digit code to compare |
| `confirm_pairing` | Asks you whether the codes match (or takes your answer as `codes_match` in a client that cannot ask), then confirms or cancels |
| `wallet_status`, `end_session` | Whether a wallet is paired and what it declared; unpair |
| `get_rules` | Your rules for this agent from the wallet (spec 9.4): actions, assets, limits per trade and per day or week with what is left (open offers count), price bands, hours, expiry, pause |
| `get_balances` | Spendable and confirmed balances for XCH and CATs |
| `take_offer` | Asks the wallet to take an `offer1…` |
| `create_offer` | Asks the wallet to make an offer, expiring (default 60 minutes); records it |
| `cancel_offer` | Asks the wallet to cancel one of the agent's offers, on chain |
| `list_offers` | The offers made through this pairing |
| `request_status`, `cancel_request` | A request still waiting for the wallet (or for you): wait again, or withdraw it |
| `origin_document` | The `.well-known/xchonnect.json` to publish for your own domain |

`take_offer`, `create_offer` and `cancel_offer` have a `dry_run` that returns what would be
asked without contacting the wallet. Amounts are in units ("0.25" XCH, "12.5" of a CAT) and are
converted to mojos exactly; an amount with more decimals than the asset has is refused. A
network fee above `XCHONNECT_MCP_MAX_FEE` (default 0.01 XCH) is refused before the wallet sees it.

A wallet without agent rules (Klimper today) may ignore an offer's expiry: the offer then stays
takeable until it is cancelled or taken, and `list_offers` keeps it open (`expiry_enforced:
false`) instead of guessing from the clock.

Every failure is one code from a fixed list. The wallet's refusals by your rules: `paused`,
`expired`, `outside_hours`, `action_not_allowed`, `asset_not_allowed`, `price_out_of_band`,
`limit_per_trade`, `limit_per_period`. The rest: `not_paired`, `pairing_expired`,
`pairing_rejected`, `session_ended`, `wallet_unreachable` (the request is
queued until the wallet comes online), `relay_unreachable`, `user_rejected`,
`insufficient_balance`, `not_supported`, `cannot_decode`, `no_key`, `refused` (another wallet
policy), `invalid_request`, `request_expired`, `cancelled`, `not_set_up` (no origin, no keychain, or nodexch or the relay unreachable at start: the message says which; the setup is tried again on a tool call at most every 15 s, so the plugin answers the client at once and recovers without a restart), `internal`.

## Settings

| Variable | Default | |
| --- | --- | --- |
| `XCHONNECT_RELAY` | `https://relay.nodexch.com` | The relay (with `NODEXCH_KEY`: nodexch's, leave it unset) |
| `NODEXCH_KEY` | | The agent's secret nodexch key: nodexch signs the pairing (no domain of your own needed) |
| `NODEXCH_URL` | `https://api.nodexch.com` | nodexch's API, for `NODEXCH_KEY` |
| `XCHONNECT_AGENT_NAME` | `Claude Code agent` | The name in the origin document |
| `XCHONNECT_ORIGIN_DOMAIN`, `XCHONNECT_ORIGIN_KID` | none, `agent-1` | Your own origin |
| `XCHONNECT_DEV`, `XCHONNECT_DEV_PORT` | off, `8797` | Developer mode |
| `XCHONNECT_MCP_DIR` | `~/.xchonnect-mcp` | The encrypted state file and the QR image |
| `XCHONNECT_MCP_KEY_FILE` | none: the system keychain | Keep the state key in a file instead |
| `XCHONNECT_MCP_MAX_FEE` | `0.01` | The largest network fee a request may carry, in XCH |
| `XCHONNECT_MCP_NO_VIEWER` | off | Never open the QR image |
| `XCHONNECT_MCP_DEBUG` | off | Log amounts, assets and offers too |

## Security

- **What the plugin holds:** the session's secrets and the origin key, in one file
  (`state.bin`) encrypted with AES-256-GCM under a key in the macOS Keychain or the Linux Secret
  Service (`secret-tool`); with `XCHONNECT_MCP_KEY_FILE`, in a file of its own (mode 0600), which
  is weaker. The keychain item can be read without a prompt by any program running as you
  (that is how the plugin reads it), so against malware on your account it protects about as
  much as the file; it keeps the key out of backups and synced copies of your home directory.
  Whoever has both the file and the key has the session and the origin key. Windows has no
  keychain support yet.
  `end_session`, or ending the pairing in the wallet, revokes the session; removing the
  directory forgets it.
- **What a compromised machine can do:** whoever controls the plugin's host (or the agent) can
  send the wallet any request the session allows. Within the rules you set for the agent, the
  wallet answers without asking you, so they can trade up to your limits, in your assets, at
  prices in your bands, until you pause or unpair the agent in the wallet. They cannot take the
  wallet's keys, go past a rule, or move funds the rules do not allow without your approval in
  the wallet. Set the limits to what you would accept losing.
- **What the agent can be told:** market data, offers and chat text may carry instructions
  aimed at the agent. They can make it *propose* a trade; whether the trade happens is the
  wallet's decision under your rules. Check offers with nodexch `decode_offer` or the wallet's
  own display.
- **Logs** (stderr) say what happened, never with what: no amounts, assets, addresses, offers
  or pairing strings unless `XCHONNECT_MCP_DEBUG=1`.
- The pairing QR code and string are a secret for five minutes, and they also end up in the
  chat transcript: whoever uses them first pairs, and the code comparison (asked of you, not
  the model, where the client can ask) is what catches that.
- Text from the wallet (its rules, refusals) reaches the agent reduced to the fields of the
  protocol and bounded in length.
- **The relay sees this machine's IP address.** The plugin talks to the relay directly, not
  through Oblivious HTTP (it has no OHTTP option), and keeps listening for as long as it is
  paired, so the relay operator can see the agent machine's IP address for the pairing's whole
  life, at the network layer (the relay does not read or store it; its proxy may log it). The
  messages stay end-to-end encrypted.
- **Where the client cannot ask you, the code check rests on the agent.** With a client that
  supports elicitation, `confirm_pairing` asks you directly whether the wallet shows the same
  6-digit code. Without it, `codes_match` is whatever the model passes: the comparison then
  rests on the agent asking you and repeating your answer truthfully, and an agent misled by
  text in the chat could confirm a pairing you did not check. Compare the codes yourself, and
  if in doubt end the session in the wallet.

## Limitations

- The rules and the refusal codes (spec 9.4, draft) need a wallet that implements them; Klimper
  does not yet (clapandpay-backlog TASK-143), and a wallet without them answers `get_rules` with
  `not_supported` and treats the agent as a dApp.
- Pairing needs an origin: your own domain or developer mode.
- The plugin does not decode offers itself; the wallet does before it signs, and nodexch
  `decode_offer` does for the agent.
- `list_offers` knows what was made and cancelled through it, not whether an offer was taken.
- Klimper does not take `expiresAt` yet, so its offers do not expire (see above).
- Runs locally over stdio only; a remote (Streamable HTTP) mode for hosted agents is planned.

## Development

A member of the repository's npm workspace, run from the root:

```sh
npm ci --ignore-scripts && npm run build -w @xchonnect/dapp
npm test -w @xchonnect/mcp    # unit tests, the spec 9.4 vectors, the end-to-end test
```

The plugin and the tests' wallet side both run on this repository's SDK build (`../sdk-ts`,
which the workspace links as `@xchonnect/dapp`; it is released together with the plugin at
the same version), whose test wallet sends refusal reasons; the end-to-end test
pairs the plugin with a test wallet that enforces the rules of spec 9.4 over the relay API in
memory. `test/demo/wallet.demo.ts` runs that test wallet as a process against a real relay, for
trying the plugin in Claude Code without a phone (see its header).
