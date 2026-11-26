import Foundation
import Combine
import Security
import Network
import UIKit

enum AgentError: Error {
    case keychain(OSStatus), response, invalidURL, invalidCommand
}

enum Credential {
    static let device = "JARVIS-IP8-001"
    static let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.jarvis.device-agent.gateway",
        kSecAttrAccount as String: device
    ]

    static func save(_ value: String) throws {
        let data = Data(value.utf8)
        var status = SecItemUpdate(query as CFDictionary, [
            kSecValueData as String: data
        ] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw AgentError.keychain(status) }
    }

    static func load() throws -> String? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw AgentError.keychain(status) }
        guard let data = value as? Data else { throw AgentError.response }
        return String(data: data, encoding: .utf8)
    }
}

// Provisional wire format. Confirm these types and Gateway against JDB-1 Phase 2.
struct Command: Decodable {
    let command_id: String
    let command: String
    let issued_at: Date
}

struct CommandResult: Codable {
    let command_id: String
    let status: String
    let data: [String: String]
}

final class RejectRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

struct Gateway {
    let base: URL
    let credential: String
    private static let session = URLSession(configuration: .ephemeral,
                                            delegate: RejectRedirect(), delegateQueue: nil)

    init(address: String, credential: String) throws {
        guard let parts = URLComponents(string: address), parts.scheme == "https",
              let host = parts.host, !host.isEmpty, parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil, let url = parts.url else {
            throw AgentError.invalidURL
        }
        self.base = url
        self.credential = credential
    }

    private func request(_ endpoint: String) -> URLRequest {
        var request = URLRequest(url: base.appendingPathComponent(endpoint), timeoutInterval: 10)
        request.setValue("Bearer " + credential, forHTTPHeaderField: "Authorization")
        request.setValue(Credential.device, forHTTPHeaderField: "X-Device-ID")
        return request
    }

    func poll() async throws -> Command? {
        let (data, response) = try await Self.session.data(for: request("commands"))
        switch (response as? HTTPURLResponse)?.statusCode {
        case 204: return nil
        case 200:
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(Command.self, from: data)
        default: throw AgentError.response
        }
    }

    func submit(_ result: CommandResult) async throws {
        var request = request("results")
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(result)
        let (_, response) = try await Self.session.data(for: request)
        guard let status = (response as? HTTPURLResponse)?.statusCode,
              (200..<300).contains(status) else { throw AgentError.response }
    }
}

struct CachedResult: Codable {
    let action: String
    let issuedAt: Date
    let result: CommandResult
}

@MainActor
final class Agent: ObservableObject {
    @Published private(set) var status = "Sin conexión"
    private var active = false
    private let monitor = NWPathMonitor()

    init() {
        UIDevice.current.isBatteryMonitoringEnabled = true
        monitor.start(queue: DispatchQueue(label: "com.jarvis.network"))
    }

    deinit { monitor.cancel() }

    func run(address: String) async {
        while active {
            do { try await Task.sleep(nanoseconds: 50_000_000) }
            catch { return }
        }
        guard !Task.isCancelled else { return }
        active = true
        defer { active = false }
        do {
            guard let credential = try Credential.load() else {
                status = "Configura la credencial"
                return
            }
            let gateway = try Gateway(address: address, credential: credential)
            let store = try FileManager.default.url(for: .applicationSupportDirectory,
                                                     in: .userDomainMask,
                                                     appropriateFor: nil, create: true)
                .appendingPathComponent("command-results.json")
            let origin = gateway.base.absoluteString
            var cache: [String: [String: CachedResult]] = [:]
            if FileManager.default.fileExists(atPath: store.path) {
                cache = try JSONDecoder().decode([String: [String: CachedResult]].self,
                                                 from: Data(contentsOf: store))
            }
            while !Task.isCancelled {
                do {
                    if let command = try await gateway.poll() {
                        try Task.checkCancellation()
                        let age = Date().timeIntervalSince(command.issued_at)
                        if (0..<120).contains(age) {
                            guard !command.command_id.isEmpty else { throw AgentError.invalidCommand }
                            let item: CachedResult
                            if let previous = cache[origin]?[command.command_id] {
                                guard previous.action == command.command,
                                      previous.issuedAt == command.issued_at else {
                                    throw AgentError.invalidCommand
                                }
                                item = previous
                            } else {
                                item = CachedResult(action: command.command, issuedAt: command.issued_at,
                                                    result: execute(command))
                                var updated = cache
                                updated[origin, default: [:]][command.command_id] = item
                                try JSONEncoder().encode(updated).write(to: store, options: .atomic)
                                cache = updated
                            }
                            if Date().timeIntervalSince(command.issued_at) < 120 {
                                try await gateway.submit(item.result)
                            }
                        }
                    }
                    status = "Sondeo activo"
                } catch {
                    if Task.isCancelled { return }
                    status = "Error de sondeo o entrega"
                }
                try await Task.sleep(nanoseconds: 5_000_000_000)
            }
        } catch {
            if !Task.isCancelled { status = "Revisa la configuración o el registro local" }
        }
    }

    private func execute(_ command: Command) -> CommandResult {
        let data: [String: String]
        switch command.command {
        case "GET_STATUS":
            data = ["device_id": Credential.device, "state": "online"]
        case "BATTERY":
            let level = UIDevice.current.batteryLevel
            data = ["percent": level < 0 ? "unknown" : String(Int((level * 100).rounded()))]
        case "NETWORK":
            let path = monitor.currentPath
            let interfaces = path.availableInterfaces.filter { path.usesInterfaceType($0.type) }
            data = ["state": path.status == .satisfied ? "available" : "unavailable",
                    "interfaces": interfaces.map(\.name).joined(separator: ",")]
        default:
            return CommandResult(command_id: command.command_id, status: "unsupported", data: [:])
        }
        return CommandResult(command_id: command.command_id, status: "ok", data: data)
    }
}
