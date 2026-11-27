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
    static let signingService = "com.jarvis.device-agent.gateway-ed25519-public"

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

    func validate(at now: TimeInterval, allowExpired: Bool = false) throws {
        guard self.protocol == "JDB-1", device_id == Credential.device,
              let id = UUID(uuidString: command_id),
              id.uuidString.lowercased() == command_id.lowercased(),
              ["maus", "alpha", "beta", "codex"].contains(origin),
              !requires_approval,
              issued_at > 0, expires_at > issued_at, expires_at - issued_at <= 120,
              Double(issued_at) <= now, allowExpired || now < Double(expires_at) else {
            throw AgentError.invalidCommand
        }
        switch capability {
        case "GET_STATUS", "GET_BATTERY", "GET_NETWORK":
            guard payload.isEmpty else { throw AgentError.invalidCommand }
        case "SAVE_NOTE":
            guard origin != "codex", payload.count == 1, let text = payload["text"],
                  (1...500).contains(text.unicodeScalars.count),
                  !text.trimmingCharacters(in: CharacterSet(charactersIn: " \t\r\n")).isEmpty else {
                throw AgentError.invalidCommand
            }
        default:
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

enum DeliverySignature {
    static func verifies(_ signature: String, body: Data,
                         key: Curve25519.Signing.PublicKey) -> Bool {
        guard let bytes = Data(base64Encoded: signature), bytes.count == 64,
              bytes.base64EncodedString() == signature else { return false }
        var signedBytes = Data("JDB-1\n".utf8)
        signedBytes.append(body)
        return key.isValidSignature(bytes, for: signedBytes)
    }
}

struct SignedDelivery {
    let body: Data

    init(body: Data, response: HTTPURLResponse, key: Curve25519.Signing.PublicKey) throws {
        guard let signature = response.value(forHTTPHeaderField: "X-Jarvis-Ed25519"),
              response.value(forHTTPHeaderField: "Content-Type")?.lowercased() == "application/json",
              DeliverySignature.verifies(signature, body: body, key: key) else {
            throw AgentError.invalidCommand
        }
        self.body = body
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
    let signingKey: Curve25519.Signing.PublicKey
    private static let session = URLSession(configuration: .ephemeral,
                                            delegate: RejectRedirect(), delegateQueue: nil)

    init(address: String, credential: String, signingKey: Curve25519.Signing.PublicKey) throws {
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
                guard data.count < 8192 else { throw AgentError.invalidCommand }
                data.append(byte)
            }
            return try SignedDelivery(body: data, response: response, key: signingKey)
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
    var pendingUpload: Bool? = nil
}

struct DeliveryJournal: Codable {
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
                status = "Configura la credencial y la clave pública Ed25519"
                return
            }
            let gateway = try Gateway(address: address, credential: credential,
                                      signingKey: Curve25519.Signing.PublicKey(rawRepresentation: key))
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
                    for (id, entry) in journal.commands where entry.pendingUpload == true {
                        guard let result = entry.result else { throw AgentError.response }
                        try await gateway.submit(result, to: "result")
                        var updated = journal
                        updated.commands[id]?.pendingUpload = false
                        try updated.save(to: store)
                        journal = updated
                    }
                    if let delivery = try await gateway.poll() {
                        try Task.checkCancellation()
                        let command = try JSONDecoder().decode(Command.self, from: delivery.body)
                        try command.validate(at: Date().timeIntervalSince1970, allowExpired: true)
                        let id = command.command_id.lowercased()
                        guard !legacyIDs.contains(id) else { throw AgentError.invalidCommand }
                        let fingerprint = SignedDelivery.digest(delivery.body)
                        let previous = journal.commands[id]
                        guard previous == nil || previous?.fingerprint == fingerprint else {
                            throw AgentError.invalidCommand
                        }
                        try await gateway.submit(CommandAck(device_id: Credential.device,
                                                            command_id: command.command_id), to: "ack")
                        var updated = journal
                        let result: CommandResult
                        if let previous = previous {
                            result = previous.result ?? CommandResult(device_id: Credential.device,
                                command_id: command.command_id, status: "interrupted", data: [:])
                        } else {
                            try Task.checkCancellation()
                            updated.commands[id] = CachedResult(fingerprint: fingerprint, result: nil)
                            try updated.save(to: store)
                            journal = updated
                            if Date().timeIntervalSince1970 < Double(command.expires_at) {
                                result = execute(command, in: store.deletingLastPathComponent())
                            } else {
                                result = CommandResult(device_id: Credential.device,
                                    command_id: command.command_id, status: "interrupted", data: [:])
                            }
                        }
                        updated.commands[id]?.result = result
                        updated.commands[id]?.pendingUpload = true
                        try updated.save(to: store)
                        journal = updated
                        try await gateway.submit(result, to: "result")
                        updated.commands[id]?.pendingUpload = false
                        try updated.save(to: store)
                        journal = updated
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

    private func execute(_ command: Command, in directory: URL) -> CommandResult {
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
        case "SAVE_NOTE":
            let file = directory.appendingPathComponent("Note-" + command.command_id.lowercased() + ".txt")
            do {
                guard let text = command.payload["text"] else { throw AgentError.invalidCommand }
                try Data(text.utf8).write(to: file, options: .atomic)
                data = ["note_id": command.command_id]
            } catch {
                return CommandResult(device_id: Credential.device, command_id: command.command_id,
                                     status: "error", data: [:])
            }
        default:
            return CommandResult(device_id: Credential.device, command_id: command.command_id,
                                 status: "error", data: [:])
        }
        return CommandResult(device_id: Credential.device, command_id: command.command_id,
                             status: "ok", data: data)
    }
}
