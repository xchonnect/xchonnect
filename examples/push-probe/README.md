# Push probe (development only)

Checks a push gateway's APNs delivery against a real iPhone (TASK-46): a command-line tool
that does what a relay does, and a minimal iOS app that registers for push and shows its
device token. Never point it at production device tokens of real users.

| Part | What it does |
|---|---|
| `xchonnect-push-probe` (this crate) | `keys` lists the gateway's public keys; `seal` seals a device token to one (spec 7.3.2); `wake` seals, posts to `/v1/wake` and prints the gateway counters before and after |
| `ios/` | **Push Probe** app: asks for notification permission, registers with APNs, shows the device token with a copy button, lists every notification it receives with its interruption level |

The wake response is the same `202 {}` for every request (the gateway is no oracle), so the
result is read from `/metrics`: `delivered_total` for a push Apple accepted,
`invalid_device_total` and `forgotten_total` for a token Apple refused, `failed_total` for
anything else, with the reason in the gateway log.

## What you need

- An APNs auth key (`.p8`) with its **Key ID** and your **Team ID**. Developer portal →
  Certificates, Identifiers & Profiles → Keys → **+** → *Apple Push Notifications service
  (APNs)*, environment *Sandbox & Production*. It downloads once; keep it in a password
  manager.
- An iPhone with Developer Mode on (Settings → Privacy & Security → Developer Mode),
  connected to the Mac, and Xcode signed in to the same team.
- A bundle id for the probe app that the key may push to. A team-scoped key covers every
  app of the team.

## 1. Start the gateway with the key

```sh
mkdir -p deploy/secrets && cp ~/Downloads/AuthKey_XXXXXXXXXX.p8 deploy/secrets/apns.p8
chmod 600 deploy/secrets/apns.p8          # deploy/secrets/ is git-ignored

export XCHONNECT_GATEWAY_KEYS=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
export XCHONNECT_GATEWAY_APNS_TEAM_ID=<team id>
export XCHONNECT_GATEWAY_APNS_KEY_ID=<key id>
export XCHONNECT_GATEWAY_APNS_KEY_FILE=deploy/secrets/apns.p8
export XCHONNECT_GATEWAY_APNS_TOPIC=<probe bundle id>
export XCHONNECT_GATEWAY_APNS_ENV=sandbox  # apps run from Xcode use the APNs sandbox
cargo run -p xchonnect-gateway             # 127.0.0.1:8788
```

A `.p8` that the gateway cannot use stops it at start-up with
`APNs .p8 is not an unencrypted PKCS#8 P-256 key`.

## 2. Check the key against Apple, before any phone is involved

Wake a made-up device token. Apple only looks at the token after it has accepted the
provider token, so a *bad device token* answer proves the key, Key ID and Team ID work:

```sh
cargo run -q -p xchonnect-push-probe -- wake http://127.0.0.1:8788 --sandbox \
  --token 0000000000000000000000000000000000000000000000000000000000000000
```

- `invalid_device_total` and `forgotten_total` +1: **the key works.**
- `failed_total` +1 and `InvalidProviderToken` or `ExpiredProviderToken` in the gateway
  log: the Key ID, Team ID or `.p8` does not match.

## 3. Install the probe app on the iPhone

```sh
cd examples/push-probe/ios
xcodegen generate                          # brew install xcodegen
xcodebuild -project PushProbe.xcodeproj -scheme PushProbe \
  -destination 'platform=iOS,name=<your iPhone>' -allowProvisioningUpdates \
  DEVELOPMENT_TEAM=<team id> PUSH_PROBE_BUNDLE_ID=<probe bundle id> build
xcrun devicectl device install app --device '<your iPhone>' \
  build/Build/Products/Debug-iphoneos/PushProbe.app   # or Run from Xcode
```

`-allowProvisioningUpdates` lets Xcode register the bundle id with the Push Notifications
and Time Sensitive Notifications capabilities. Open the app, allow notifications, tap
**Copy device token** and get the token to the Mac (AirDrop, Universal Clipboard).

## 4. Wake the phone in each state

```sh
cargo run -q -p xchonnect-push-probe -- wake http://127.0.0.1:8788 --sandbox --token <device token>
```

Run it three times and note what the phone shows:

1. **App in front**: a banner, and the *Received* list gains `foreground: … (time-sensitive)`.
2. **App suspended** (home screen, app still in the switcher): the notification arrives on
   the lock screen or as a banner; opening it adds `opened: …`.
3. **App closed** (swiped away in the switcher): the same.

Each time `delivered_total` must rise by one, and the notification must show only the
gateway's generic text (`XCHONNECT_GATEWAY_APNS_ALERT_TITLE` / `_BODY`), no amounts or
addresses.

## 5. A token Apple has invalidated

Delete the app, wait a few minutes, and wake the old token again: `invalid_device_total`
and `forgotten_total` rise, `delivered_total` does not, and the wake response is still the
same `202 {}`.

Record the results (date, iOS version, which states delivered, the interruption level
shown) in TASK-46.
