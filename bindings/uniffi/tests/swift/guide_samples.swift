// Code samples for docs/wallet-integration.md. Compiled (not run) by scripts/test-swift.sh
// so the guide cannot drift from the generated API.
import Foundation

// MARK: - Relay client (minimal)

/// Rejects redirects: origin documents and relay calls must never follow them (spec 6.1, 7.3.1).
final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

let http = URLSession(configuration: .ephemeral, delegate: NoRedirects(), delegateQueue: nil)

struct RelayError: Error { let status: Int; let code: String }

func relayCall(_ base: String, _ method: String, _ path: String, token: String? = nil, body: [String: Any]? = nil) async throws -> [String: Any] {
    var req = URLRequest(url: URL(string: base + path)!)
    req.httpMethod = method
    if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
    if let body {
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
    }
    let (data, response) = try await http.data(for: req)
    let status = (response as? HTTPURLResponse)?.statusCode ?? 0
    let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    guard (200..<300).contains(status) else { throw RelayError(status: status, code: json["error"] as? String ?? "unavailable") }
    return json
}

/// Create a mailbox using a sponsorship ticket from the URI, or proof-of-work.
func createMailbox(relay: String, tokens: MailboxTokens, ticket: String?) async throws -> String {
    var body: [String: Any] = ["read_token_hash": tokens.readTokenHash, "write_token_hash": tokens.writeTokenHash]
    let info = try await relayCall(relay, "GET", "/v1/info")
    let methods = info["mailbox_creation"] as? [String] ?? []
    if let ticket, methods.contains("ticket") {
        body["ticket"] = ticket
    } else if methods.contains("pow") {
        let challenge = try await relayCall(relay, "POST", "/v1/challenge")["challenge"] as! String
        let nonce = try await Task.detached { try solvePow(challenge: challenge) }.value // CPU-bound: off the main thread
        body["pow"] = ["challenge": challenge, "nonce": nonce]
    }
    return try await relayCall(relay, "POST", "/v1/mailboxes", body: body)["mailbox_id"] as! String
}

func post(_ relay: String, _ out: Outgoing) async throws {
    _ = try await relayCall(relay, "POST", "/v1/mailboxes/\(out.mailbox)/messages", token: out.writeToken, body: ["env": out.envelope])
}

// MARK: - Pairing

/// Scan → verify → show the verified domain → reply. Returns the pending pairing and SAS.
func pair(scanned uri: String, walletName: String) async throws -> (WalletPairing, String, String) {
    let info = try inspectUri(uri: uri, developerMode: false)
    var req = URLRequest(url: URL(string: info.originDocumentUrl)!)
    req.httpShouldHandleCookies = false
    let (doc, _) = try await http.data(for: req)                      // HTTPS, no redirects, ≤ 16 KiB
    let verified = try VerifiedPairingUri(uri: uri, originDocumentJson: String(decoding: doc.prefix(16 * 1024), as: UTF8.self),
                                          now: UInt64(Date().timeIntervalSince1970), developerMode: false)
    let display = verified.domainDisplay()
    // UI: show display.unicode prominently, display.ascii if it differs, every warning, and
    // verified.dappName(); never offer "continue anyway" on failures (spec 6.3).
    _ = display
    let tokens = generateMailboxTokens()
    let mailbox = try await createMailbox(relay: info.relay, tokens: tokens, ticket: info.ticket)
    let reply = try verified.reply(now: UInt64(Date().timeIntervalSince1970),
                                   ownMailbox: NewMailbox(mailbox: mailbox, readToken: tokens.readToken, writeToken: tokens.writeToken),
                                   meta: WalletMetadata(name: walletName, icon: nil, link: "https://wallet.example/app"))
    do {
        try await post(info.relay, reply.outgoing)
    } catch let e as RelayError where e.code == "not_found" {
        // spec 6.3 step 7: the code was already used — another device may have paired.
        throw e
    }
    return (reply.pairing, reply.pairing.sas(), info.relay)
}

// MARK: - Requests

final class EnclaveSigner: WalletSigner {
    func sign(publicKey: String, message: Data) -> Data? {
        // Unwrap the BLS key with biometrics (Secure Enclave-wrapped), sign with the
        // augmented scheme, zeroize, return 96 bytes. nil = cancelled / unavailable.
        nil
    }
}

final class ApprovalScreen: WalletApprover {
    func approve(promptJson: String) -> Bool {
        // Render summary.assets (net = guaranteed effect; conditional_received only if the
        // counterparty completes), unknown_puzzles as "Unknown contract", plan.ours[].is_unsafe
        // in red, binding.bound_payments for partial requests. Return the user's decision.
        false
    }
}

final class KeychainLimits: LimitStorage {
    var stored: String?
    func load() -> String? { stored }
    func save(json: String) -> Bool { stored = json; return true }
}

/// Answer one decrypted request.
func answer(session: Session, message: IncomingMessage, context: WalletRequestContext, relay: String) async throws {
    guard case let .rpcRequest(method, _, paramsJson) = message.body else { return }
    let now = UInt64(Date().timeIntervalSince1970)
    try await post(relay, try session.received(now: now, requestId: message.id))
    let outcome = try handleWalletRequest(method: method, paramsJson: paramsJson, context: context,
                                          signer: EnclaveSigner(), approver: ApprovalScreen(), limits: KeychainLimits())
    let out: Outgoing
    switch outcome {
    case let .success(resultJson):
        out = try session.respond(now: now, requestId: message.id, resultJson: resultJson)
    case let .failure(code, msg, data):
        out = try session.respondError(now: now, requestId: message.id, code: code, message: msg, dataJson: data)
    }
    // Persist the session BEFORE posting (spec 5.3 sender state-loss rule).
    try saveToKeychain(try session.toBytes())
    try await post(relay, out)
}

func saveToKeychain(_ state: Data) throws {
    // kSecClassGenericPassword, kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
}

// MARK: - Push

/// Register for wake-ups with the vendor's gateway (fresh sealed token per session).
func registerPush(relay: String, mailbox: String, readToken: String, apnsToken: Data, gatewayKey: String) async throws -> PushRegistration {
    let reg = try sealPushToken(gatewayUrl: "https://push.wallet.example/v1/wake", gatewayPublicKey: gatewayKey,
                                platform: .apns, deviceToken: apnsToken.map { String(format: "%02x", $0) }.joined(),
                                now: UInt64(Date().timeIntervalSince1970), lifetimeS: 60 * 60 * 24 * 30)
    _ = try await relayCall(relay, "PUT", "/v1/mailboxes/\(mailbox)/push", token: readToken,
                            body: ["push_reg": ["gateway_url": reg.gatewayUrl, "sealed_token": reg.sealedToken]])
    return reg
}
