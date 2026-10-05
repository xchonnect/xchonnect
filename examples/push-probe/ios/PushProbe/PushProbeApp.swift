// Push probe (development only). Asks for notification permission, registers with APNs
// and shows the device token so it can be pasted into `xchonnect-push-probe wake`.
// Every notification that reaches the app is listed with its time and interruption
// level; one that arrives while the app is closed or suspended shows on the lock screen.

import SwiftUI
import UIKit
import UserNotifications

@MainActor
final class Probe: ObservableObject {
    static let shared = Probe()
    @Published var token: String?
    @Published var status = "Not registered"
    @Published var received: [String] = []

    func log(_ line: String) {
        let time = Date.now.formatted(date: .omitted, time: .standard)
        received.insert("\(time)  \(line)", at: 0)
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task { @MainActor in
            Probe.shared.token = hex
            Probe.shared.status = "Registered"
        }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Task { @MainActor in Probe.shared.status = "APNs registration failed: \(error.localizedDescription)" }
    }

    // A wake-up while the app is in front: show it as a banner as well, and list it.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping @Sendable (UNNotificationPresentationOptions) -> Void
    ) {
        let line = Self.describe(notification, as: "foreground")
        Task { @MainActor in Probe.shared.log(line) }
        completionHandler([.banner, .sound, .list])
    }

    // Opening a wake-up from the lock screen or banner, after a closed or suspended start.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping @Sendable () -> Void
    ) {
        let line = Self.describe(response.notification, as: "opened")
        Task { @MainActor in Probe.shared.log(line) }
        completionHandler()
    }

    private nonisolated static func describe(_ notification: UNNotification, as how: String) -> String {
        let content = notification.request.content
        let level = switch content.interruptionLevel {
        case .passive: "passive"
        case .active: "active"
        case .timeSensitive: "time-sensitive"
        case .critical: "critical"
        @unknown default: "unknown"
        }
        return "\(how): \(content.title) (\(level))"
    }
}

@main
struct PushProbeApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var probe = Probe.shared

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                List {
                    Section("APNs") {
                        Text(probe.status)
                        if let token = probe.token {
                            Text(token).font(.footnote.monospaced()).textSelection(.enabled)
                            Button("Copy device token") { UIPasteboard.general.string = token }
                        }
                        Button("Register for push") { Task { await register() } }
                    }
                    Section("Received") {
                        if probe.received.isEmpty {
                            Text("Nothing yet").foregroundStyle(.secondary)
                        }
                        ForEach(probe.received, id: \.self) { Text($0).font(.footnote) }
                    }
                }
                .navigationTitle("Push Probe")
            }
            .task { await register() }
        }
    }

    @MainActor
    private func register() async {
        let center = UNUserNotificationCenter.current()
        let granted = (try? await center.requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        probe.status = granted ? "Permission granted, registering…" : "Notifications not allowed (Settings → Push Probe)"
        UIApplication.shared.registerForRemoteNotifications()
    }
}
