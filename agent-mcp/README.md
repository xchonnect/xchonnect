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
as an image and Claude shows it as text too; scan it with the wallet, compare the 6-digit code
Claude shows with the one the wallet shows, and say whether they match. Only then is the session
used. It lasts across chats and restarts until the wallet ends it.

The wallet must check the pairing code's origin (spec 6.1), so the plugin needs one of:

- **Your own domain:** `XCHONNECT_ORIGIN_DOMAIN=agent.example.org` (and optionally
  `XCHONNECT_ORIGIN_KID`), and the document from the `origin_document` tool served at
  `https://agent.example.org/.well-known/xchonnect.json`.
- **Developer mode:** `XCHONNECT_DEV=1`. The plugin serves the document itself on
  `http://localhost:8797` and uses `http://127.0.0.1:8787` as the relay unless
  `XCHONNECT_RELAY` says otherwise. Only wallets in developer mode accept it; never for funds.

```sh
claude mcp add xchonnect -e XCHONNECT_DEV=1 -- npx -y @xchonnect/mcp
```

Pairing an agent without a domain of its own (named by you at pairing, checked by the code
alone) is not in the protocol yet; see the limitations below.

## Tools

| Tool | What it does |
| --- | --- |
| `pair` | Starts pairing: the QR code as an image (opened) and as text, and the pairing string |
| `pairing_status` | Waits for the wallet to scan; returns the 6-digit code to compare |
| `confirm_pairing` | `codes_match`: what you answered. Confirms or cancels the pairing |
| `wallet_status`, `end_session` | Whether a wallet is paired and what it declared; unpair |
| `get_rules` | Your rules for this agent from the wallet (spec 9.4): actions, assets, limits per trade and per day or week with what is left (open offers count), price bands, hours, expiry, pause |
| `get_balances` | Spendable and confirmed balances for XCH and CATs |
| `take_offer` | Asks the wallet to take an `offer1…` |
| `create_offer` | Asks the wallet to make an offer, optionally expiring; records it |
| `cancel_offer` | Asks the wallet to cancel one of the agent's offers (on chain with a fee) |
| `list_offers` | The offers made through this pairing |
| `request_status`, `cancel_request` | A request still waiting for the wallet (or for you): wait again, or withdraw it |
| `origin_document` | The `.well-known/xchonnect.json` to publish for your own domain |

`take_offer`, `create_offer` and `cancel_offer` have a `dry_run` that returns what would be
asked without contacting the wallet. Amounts are in units ("0.25" XCH, "12.5" of a CAT) and are
converted to mojos exactly; an amount with more decimals than the asset has is refused.

Every failure is one code from a fixed list. The wallet's refusals by your rules: `paused`,
`expired`, `outside_hours`, `action_not_allowed`, `asset_not_allowed`, `price_out_of_band`,
`limit_per_trade`, `limit_per_period`. The rest: `not_paired`, `pairing_expired`,
`pairing_rejected`, `session_ended`, `session_expired`, `wallet_unreachable` (the request is
queued until the wallet comes online), `relay_unreachable`, `user_rejected`,
`insufficient_balance`, `not_supported`, `cannot_decode`, `no_key`, `refused` (another wallet
policy), `invalid_request`, `request_expired`, `cancelled`, `not_set_up` (no origin, or no keychain: the message says which), `internal`.

## Settings

| Variable | Default | |
| --- | --- | --- |
| `XCHONNECT_RELAY` | `https://relay.nodexch.space` | The relay |
| `XCHONNECT_AGENT_NAME` | `Claude Code agent` | The name in the origin document |
| `XCHONNECT_ORIGIN_DOMAIN`, `XCHONNECT_ORIGIN_KID` | none, `agent-1` | Your own origin |
| `XCHONNECT_DEV`, `XCHONNECT_DEV_PORT` | off, `8797` | Developer mode |
| `XCHONNECT_MCP_DIR` | `~/.xchonnect-mcp` | The encrypted state file and the QR image |
| `XCHONNECT_MCP_KEY_FILE` | none: the system keychain | Keep the state key in a file instead |
| `XCHONNECT_MCP_NO_VIEWER` | off | Never open the QR image |
| `XCHONNECT_MCP_DEBUG` | off | Log amounts, assets and offers too |

## Security

- **What the plugin holds:** the session's secrets and the origin key, in one file
  (`state.bin`) encrypted with AES-256-GCM under a key in the macOS Keychain or the Linux Secret
  Service (`secret-tool`); with `XCHONNECT_MCP_KEY_FILE`, in a file of its own (mode 0600), which
  is weaker: whoever reads both files has the session. Windows has no keychain support yet.
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
- The pairing QR code is a secret for five minutes: whoever scans it first pairs, and the code
  comparison is what catches that.

## Limitations

- The rules and the refusal codes (spec 9.4, draft) need a wallet that implements them; Klimper
  does not yet (clapandpay-backlog TASK-143), and a wallet without them answers `get_rules` with
  `not_supported` and treats the agent as a dApp.
- Pairing needs an origin: your own domain or developer mode.
- The plugin does not decode offers itself; the wallet does before it signs, and nodexch
  `decode_offer` does for the agent.
- `list_offers` knows what was made and cancelled through it, not whether an offer was taken.
- Runs locally over stdio only; a remote (Streamable HTTP) mode for hosted agents is planned.

## Development

```sh
npm ci && npm test            # unit tests, the spec 9.4 vectors, the end-to-end test
```

The tests' wallet side runs on this repository's SDK build (`../sdk-ts`, `npm run build -w
@xchonnect/dapp` from the root), whose test wallet sends refusal reasons; the end-to-end test
pairs the plugin with a test wallet that enforces the rules of spec 9.4 over the relay API in
memory. `test/demo/wallet.demo.ts` runs that test wallet as a process against a real relay, for
trying the plugin in Claude Code without a phone (see its header).
