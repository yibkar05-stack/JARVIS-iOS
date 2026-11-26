import Foundation
import Combine
import CryptoKit
import Security
import Network
import UIKit

enum AgentError: Error {
    case keychain(OSStatus), response, invalidURL, invalidCommand
}

enum Credential {
    static let device = "JARVIS-IP8-001"
    static let bearerService = "com.jarvis.device-agent.gateway"
    static let signingService = "com.jarvis.device-agent.gateway-lab-signing"

    static func query(_ service: String) -> [String: Any] { [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: device
    ] }

    static func save(_ value: String, service: String = bearerService) throws {
        let query = query(service)
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

    static func load(service: String = bearerService) throws -> String? {
        var request = query(service)
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

struct Command: Decodable {
    let `protocol`: String
    let device_id: String
    let command_id: String
    let origin: String
    let capability: String
    let issued_at: Int64
    let expires_at: Int64
    let requires_approval: Bool
    let payload: [String: String]

    func validate(at now: TimeInterval) throws {
        guard self.protocol == "JDB-1", device_id == Credential.device,
              let id = UUID(uuidString: command_id),
              id.uuidString.lowercased() == command_id.lowercased(),
              ["maus", "alpha", "beta", "codex"].contains(origin),
              ["GET_STATUS", "GET_BATTERY", "GET_NETWORK"].contains(capability),
              !requires_approval, payload.isEmpty,
              issued_at > 0, expires_at > issued_at, expires_at - issued_at <= 120,
              Double(issued_at) <= now, now < Double(expires_at) else {
            throw AgentError.invalidCommand
        }
    }
}

struct CommandResult: Codable {
    let device_id: String
    let command_id: String
    let status: String
    let data: [String: String]
}

struct CommandAck: Encodable {
    let device_id: String
    let command_id: String
    let status = "ACKED"
}

struct SignedDelivery {
    static let keyID = "gateway-dev"
    let body: Data
    let nonce: String

    init(body: Data, response: HTTPURLResponse, key: SymmetricKey, now: TimeInterval) throws {
        func header(_ name: String) -> String { response.value(forHTTPHeaderField: name) ?? "" }
        let keyID = header("X-Jarvis-Key-Id")
        let timestamp = header("X-Jarvis-Timestamp")
        let nonce = header("X-Jarvis-Nonce")
        let requestID = header("X-Jarvis-Request-Id")
        let signature = header("X-Jarvis-Signature")
        guard keyID == Self.keyID,
              let epoch = Int64(timestamp), epoch > 0, String(epoch) == timestamp,
              abs(now - Double(epoch)) <= 60,
              nonce.range(of: #"\A[a-f0-9]{32}\z"#, options: .regularExpression) != nil,
              requestID.range(of: #"\A[a-f0-9]{32}\z"#, options: .regularExpression) != nil,
              signature.range(of: #"\A[A-Za-z0-9_-]{43}\z"#, options: .regularExpression) != nil,
              let tag = Data(base64Encoded: signature.replacingOccurrences(of: "-", with: "+")
                  .replacingOccurrences(of: "_", with: "/") + "="),
              tag.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                  .replacingOccurrences(of: "/", with: "_").dropLast() == signature[...],
              header("Content-Type").lowercased() == "application/json",
              body.count <= 512 else { throw AgentError.invalidCommand }

        let canonical = ["JARVIS-HMAC-V1", keyID, timestamp, nonce, requestID,
                         "GET", "/task", Self.digest(body)].joined(separator: "\n")
        guard HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: Data(canonical.utf8),
                                                      using: key) else {
            throw AgentError.invalidCommand
        }
        self.body = body
        self.nonce = nonce
    }

    static func digest(_ body: Data) -> String {
        SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
    }
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
    let signingKey: SymmetricKey
    private static let session = URLSession(configuration: .ephemeral,
                                            delegate: RejectRedirect(), delegateQueue: nil)

    init(address: String, credential: String, signingKey: SymmetricKey) throws {
        guard let parts = URLComponents(string: address), parts.scheme == "https",
              let host = parts.host, !host.isEmpty, parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/", let url = parts.url else {
            throw AgentError.invalidURL
        }
        self.base = url
        self.credential = credential
        self.signingKey = signingKey
    }

    private func request(_ endpoint: String) -> URLRequest {
        var request = URLRequest(url: base.appendingPathComponent(endpoint), timeoutInterval: 10)
        request.setValue("Bearer " + credential, forHTTPHeaderField: "Authorization")
        request.setValue(Credential.device, forHTTPHeaderField: "X-Device-ID")
        return request
    }

    func poll() async throws -> SignedDelivery? {
        let (bytes, response) = try await Self.session.bytes(for: request("task"))
        guard let response = response as? HTTPURLResponse else { throw AgentError.response }
        switch response.statusCode {
        case 204: return nil
        case 200:
            var data = Data()
            for try await byte in bytes {
                guard data.count < 512 else { throw AgentError.invalidCommand }
                data.append(byte)
            }
            return try SignedDelivery(body: data, response: response, key: signingKey,
                                      now: Date().timeIntervalSince1970)
        default: throw AgentError.response
        }
    }

    func submit<T: Encodable>(_ payload: T, to endpoint: String) async throws {
        var request = request(endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(payload)
        let (_, response) = try await Self.session.data(for: request)
        guard let status = (response as? HTTPURLResponse)?.statusCode,
              (200..<300).contains(status) else { throw AgentError.response }
    }
}

struct CachedResult: Codable {
    let fingerprint: String
    var result: CommandResult?
}

struct DeliveryJournal: Codable {
    var nonces: [String: TimeInterval] = [:]
    var commands: [String: CachedResult] = [:]

    func save(to url: URL) throws {
        try JSONEncoder().encode(self).write(to: url, options: .atomic)
    }
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
            guard let credential = try Credential.load(),
                  let encodedKey = try Credential.load(service: Credential.signingService),
                  let key = Data(base64Encoded: encodedKey), key.count == 32 else {
                status = "Configura la credencial y la clave de laboratorio"
                return
            }
            let gateway = try Gateway(address: address, credential: credential,
                                      signingKey: SymmetricKey(data: key))
            let store = try FileManager.default.url(for: .applicationSupportDirectory,
                                                     in: .userDomainMask,
                                                     appropriateFor: nil, create: true)
                .appendingPathComponent("jdb1-delivery-journal.json")
            var journal = DeliveryJournal()
            if FileManager.default.fileExists(atPath: store.path) {
                journal = try JSONDecoder().decode(DeliveryJournal.self, from: Data(contentsOf: store))
            }
            let legacyStore = store.deletingLastPathComponent()
                .appendingPathComponent("command-results.json")
            var legacyIDs = Set<String>()
            if FileManager.default.fileExists(atPath: legacyStore.path) {
                guard let oldCache = try JSONSerialization.jsonObject(with: Data(contentsOf: legacyStore))
                    as? [String: [String: Any]] else { throw AgentError.response }
                legacyIDs = Set(oldCache.values.flatMap { $0.keys.map { $0.lowercased() } })
            }
            var delay: UInt64 = 5
            while !Task.isCancelled {
                do {
                    if let delivery = try await gateway.poll() {
                        try Task.checkCancellation()
                        let now = Date().timeIntervalSince1970
                        guard journal.nonces[delivery.nonce].map({ $0 <= now }) ?? true else {
                            throw AgentError.invalidCommand
                        }
                        var updated = journal
                        updated.nonces = journal.nonces.filter { $0.value > now }
                        updated.nonces[delivery.nonce] = now + 180
                        try updated.save(to: store)
                        journal = updated

                        let command = try JSONDecoder().decode(Command.self, from: delivery.body)
                        try command.validate(at: Date().timeIntervalSince1970)
                        let id = command.command_id.lowercased()
                        guard !legacyIDs.contains(id) else { throw AgentError.invalidCommand }
                        let fingerprint = SignedDelivery.digest(delivery.body)
                        let previous = journal.commands[id]
                        guard previous == nil || previous?.fingerprint == fingerprint else {
                            throw AgentError.invalidCommand
                        }
                        try await gateway.submit(CommandAck(device_id: Credential.device,
                                                            command_id: command.command_id), to: "ack")
                        try Task.checkCancellation()
                        try command.validate(at: Date().timeIntervalSince1970)
                        let result: CommandResult
                        if let previous = previous {
                            result = previous.result ?? CommandResult(device_id: Credential.device,
                                command_id: command.command_id, status: "interrupted", data: [:])
                        } else {
                            updated.commands[id] = CachedResult(fingerprint: fingerprint, result: nil)
                            try updated.save(to: store)
                            journal = updated
                            try command.validate(at: Date().timeIntervalSince1970)
                            result = execute(command)
                            updated.commands[id]?.result = result
                            try updated.save(to: store)
                            journal = updated
                        }
                        try await gateway.submit(result, to: "result")
                        delay = 5
                    } else {
                        delay = min(delay * 2, 60)
                    }
                    status = "Sondeo activo"
                } catch {
                    if Task.isCancelled { return }
                    status = "Error de sondeo o entrega"
                    delay = min(delay * 2, 60)
                }
                try await Task.sleep(nanoseconds: delay * 1_000_000_000)
            }
        } catch {
            if !Task.isCancelled { status = "Revisa la configuración o el registro local" }
        }
    }

    private func execute(_ command: Command) -> CommandResult {
        let data: [String: String]
        switch command.capability {
        case "GET_STATUS":
            data = ["device_id": Credential.device, "state": "online"]
        case "GET_BATTERY":
            let level = UIDevice.current.batteryLevel
            data = ["percent": level < 0 ? "unknown" : String(Int((level * 100).rounded()))]
        case "GET_NETWORK":
            let path = monitor.currentPath
            let interfaces = path.availableInterfaces.filter { path.usesInterfaceType($0.type) }
            data = ["state": path.status == .satisfied ? "available" : "unavailable",
                    "interfaces": interfaces.map(\.name).joined(separator: ",")]
        default:
            return CommandResult(device_id: Credential.device, command_id: command.command_id,
                                 status: "unsupported", data: [:])
        }
        return CommandResult(device_id: Credential.device, command_id: command.command_id,
                             status: "ok", data: data)
    }
}
