// Arnés BETA — BUILD-003 puntos 3 y 4. Se compila JUNTO al App/Agent.swift REAL (sin copias ni recortes).
import Foundation
import CryptoKit
import ObjectiveC

// ───────── Stub de red (intercepta la URLSession estática de Gateway) ─────────

final class Stub: URLProtocol {
    struct Reply { var status = 200; var headers: [String: String] = [:]; var body = Data() }
    struct Hit { let method: String; let path: String; let body: Data }
    static let lock = NSLock()
    static var taskQueue: [Reply] = []
    static var hits: [Hit] = []
    static var onTask: ((Int) -> Void)?

    static func reset() { lock.lock(); taskQueue = []; hits = []; onTask = nil; lock.unlock() }
    static func taskCount() -> Int { lock.lock(); defer { lock.unlock() }; return hits.filter { $0.path == "/task" }.count }
    static func posts(_ p: String) -> [Data] { lock.lock(); defer { lock.unlock() }; return hits.filter { $0.path == p && $0.method == "POST" }.map(\.body) }

    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "gw.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        let req = request
        var body = Data()
        if let s = req.httpBodyStream {
            s.open()
            var buf = [UInt8](repeating: 0, count: 4096)
            while s.hasBytesAvailable { let n = s.read(&buf, maxLength: buf.count); if n <= 0 { break }; body.append(buf, count: n) }
            s.close()
        } else if let b = req.httpBody { body = b }
        let method = req.httpMethod ?? "GET"
        let path = req.url?.path ?? ""
        Stub.lock.lock()
        Stub.hits.append(Hit(method: method, path: path, body: body))
        let n = Stub.hits.filter { $0.path == "/task" }.count
        Stub.lock.unlock()
        var reply = Reply(status: 200)
        if path == "/task" && method == "GET" {
            Stub.onTask?(n)
            Stub.lock.lock()
            reply = Stub.taskQueue.isEmpty ? Reply(status: 204) : Stub.taskQueue.removeFirst()
            Stub.lock.unlock()
        }
        let http = HTTPURLResponse(url: req.url!, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: reply.headers)!
        client?.urlProtocol(self, didReceive: http, cacheStoragePolicy: .notAllowed)
        if !reply.body.isEmpty { client?.urlProtocol(self, didLoad: reply.body) }
        client?.urlProtocolDidFinishLoading(self)
    }
}

func installEphemeralSwizzle() -> Bool {
    let sel = NSSelectorFromString("ephemeralSessionConfiguration")
    guard let m = class_getClassMethod(URLSessionConfiguration.self, sel) else { return false }
    typealias Fn = @convention(c) (AnyObject, Selector) -> AnyObject
    let orig = unsafeBitCast(method_getImplementation(m), to: Fn.self)
    let block: @convention(block) (AnyObject) -> AnyObject = { cls in
        let cfg = orig(cls, sel) as! URLSessionConfiguration
        cfg.protocolClasses = [Stub.self] + (cfg.protocolClasses ?? [])
        return cfg
    }
    method_setImplementation(m, imp_implementationWithBlock(block))
    return true
}

// ───────── Utilidades ─────────

let gwURL = "https://gw.test"
var tally = ["PASS": 0, "FAIL": 0, "BLOCKED": 0]

func report(_ id: String, _ title: String, _ checks: [(String, Bool)], blocked: String? = nil, obs: [String] = []) {
    let failed = checks.contains { !$0.1 }
    let state = failed ? "FAIL" : (blocked != nil ? "BLOCKED" : "PASS")
    tally[state]! += 1
    print("\(state)\(id)—\(title)")
    for (name, ok) in checks { print("  \(ok ? "ok  " : "FAIL") \(name)") }
    if let b = blocked { print("    BLOCKED: \(b)") }
    for o in obs { print("    OBS: \(o)") }
}

func sign(_ body: Data, _ k: Curve25519.Signing.PrivateKey, prefix: String = "JDB-1\n") -> String {
    var m = Data(prefix.utf8)
    m.append(body)
    return try! k.signature(for: m).base64EncodedString()
}

func response(_ headers: [String: String]) -> HTTPURLResponse {
    HTTPURLResponse(url: URL(string: "\(gwURL)/task")!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!
}

func accepts(_ body: Data, sig: String?, ct: String? = "application/json", key: Curve25519.Signing.PublicKey) -> Bool {
    var h: [String: String] = [:]
    if let s = sig { h["X-Jarvis-Ed25519"] = s }
    if let c = ct { h["Content-Type"] = c }
    return (try? SignedDelivery(body: body, response: response(h), key: key)) != nil
}

func reply(_ body: Data, sig: String?, ct: String? = "application/json") -> Stub.Reply {
    var h: [String: String] = [:]
    if let s = sig { h["X-Jarvis-Ed25519"] = s }
    if let c = ct { h["Content-Type"] = c }
    return Stub.Reply(status: 200, headers: h, body: body)
}

func commandBody(id: String = UUID().uuidString.lowercased(), cap: String = "SAVE_NOTE", text: String = "nota", issued: Int64, expires: Int64, origin: String = "alpha") -> Data {
    var payload: [String: String] = [:]
    if cap == "SAVE_NOTE" { payload["text"] = text }
    let obj: [String: Any] = ["protocol": "JDB-1", "device_id": Credential.device, "command_id": id, "origin": origin, "capability": cap, "issued_at": issued, "expires_at": expires, "requires_approval": false, "payload": payload]
    return try! JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
}

func validates(_ b: Data, at now: TimeInterval, allowExpired: Bool = false) -> Bool {
    guard let c = try? JSONDecoder().decode(Command.self, from: b) else { return false }
    return (try? c.validate(at: now, allowExpired: allowExpired)) != nil
}

let support = try! FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)

func resetState() {
    for f in (try? FileManager.default.contentsOfDirectory(atPath: support.path)) ?? [] where f.hasPrefix("Note-") || f == "jdb1-delivery-journal.json" || f == "command-results.json" {
        try? FileManager.default.removeItem(at: support.appendingPathComponent(f))
    }
    Stub.reset()
}

func noteExists(_ id: String) -> Bool {
    FileManager.default.fileExists(atPath: support.appendingPathComponent("Note-\(id).txt").path)
}

func noteDelete(_ id: String) {
    try? FileManager.default.removeItem(at: support.appendingPathComponent("Note-\(id).txt"))
}

func journal() -> DeliveryJournal? {
    guard let d = try? Data(contentsOf: support.appendingPathComponent("jdb1-delivery-journal.json")) else { return nil }
    return try? JSONDecoder().decode(DeliveryJournal.self, from: d)
}

@MainActor func e2e(_ queue: [Stub.Reply], waitTasks: Int, timeout: Double, settle: Double = 0.8) async -> String {
    Stub.lock.lock()
    Stub.taskQueue = queue
    Stub.lock.unlock()
    let agent = Agent() // instancia nueva = "app reiniciada"
    let t = Task { await agent.run(address: gwURL) }
    let end = Date().addingTimeInterval(timeout)
    while Stub.taskCount() < waitTasks && Date() < end { try? await Task.sleep(nanoseconds: 50_000_000) }
    try? await Task.sleep(nanoseconds: UInt64(settle * 1_000_000_000))
    t.cancel()
    await t.value
    return agent.status
}

// ───────── Preparación ─────────

let priv = Curve25519.Signing.PrivateKey()
let pub = priv.publicKey
let attacker = Curve25519.Signing.PrivateKey()
let nowD = Date().timeIntervalSince1970
let n = Int64(nowD)

print("== BETA client tests — BUILD-003 (Agent.swift real) ==")

let swizzled = installEphemeralSwizzle()
var e2eBlock: String? = nil
if !swizzled { e2eBlock = "no se pudo instalar el seam de URLSession" }
if e2eBlock == nil {
    do {
        try Credential.save("test-credential")
        try Credential.save(pub.rawRepresentation.base64EncodedString(), service: Credential.signingService)
    } catch {
        e2eBlock = "Keychain no disponible en el proceso de prueba: \(error)"
    }
    if e2eBlock == nil {
        resetState()
        do {
            let gw = try Gateway(address: gwURL, credential: "x", signingKey: pub)
            let r = try await gw.poll()
            if !(r == nil && Stub.taskCount() == 1) { e2eBlock = "canario: la URLSession estática no fue interceptada" }
        } catch {
            e2eBlock = "canario falló: \(error)"
        }
    }
}
print("Seam e2e: \(e2eBlock ?? "OK")")

let goodBody = commandBody(issued: n - 10, expires: n + 100)
let good = sign(goodBody, priv)
let raw = Data(base64Encoded: good)!

report("P3-0", "control: entrega válida aceptada", [
    ("SignedDelivery acepta", accepts(goodBody, sig: good, key: pub))
])

@MainActor func e2eRejects(_ r: Stub.Reply) async -> [(String, Bool)] {
    resetState()
    let st = await e2e([r], waitTasks: 1, timeout: 6, settle: 0.6)
    return [
        ("e2e: el agente sondeó", Stub.taskCount() >= 1),
        ("e2e: sin ACK ni result", Stub.posts("/ack").isEmpty && Stub.posts("/result").isEmpty),
        ("e2e: sin diario creado", (journal()?.commands.isEmpty ?? true)),
        ("e2e: estado visible = \(st)", st == "Error de sondeo o entrega")
    ]
}

@MainActor func p3(_ id: String, _ title: String, _ unit: [(String, Bool)], bad: Stub.Reply, obs: [String] = []) async {
    var checks = unit
    var o = obs
    if e2eBlock == nil { checks += await e2eRejects(bad) } else { o.append("e2e no ejecutado: \(e2eBlock!)") }
    report(id, title, checks, obs: o)
}

// ───────── PUNTO 3 — FORMATO ─────────

func b64(_ d: Data) -> String { d.base64EncodedString() }

await p3("P3-1", "firma Ed25519 de longitud ≠ 64", [
    ("63 bytes rechazada", !accepts(goodBody, sig: b64(raw.prefix(63)), key: pub)),
    ("65 bytes rechazada", !accepts(goodBody, sig: b64(raw + Data([0])), key: pub)),
    ("128 bytes rechazada", !accepts(goodBody, sig: b64(raw + raw), key: pub)),
    ("vacía rechazada", !accepts(goodBody, sig: "", key: pub)),
    ("control posterior aceptado (cliente no roto)", accepts(goodBody, sig: good, key: pub))
], bad: reply(goodBody, sig: b64(raw.prefix(63))))

let alpha = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
var ch = Array(good); let li = ch.count - 3
ch[li] = alpha[alpha.firstIndex(of: ch[li])! ^ 1]
let nonCanon = String(ch)
let urlSafe = good.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
await p3("P3-2", "firma en Base64 no canónico", [
    ("variante distinta del original", nonCanon != good),
    ("bits de relleno alterados rechazada", !accepts(goodBody, sig: nonCanon, key: pub)),
    ("sin padding rechazada", !accepts(goodBody, sig: good.replacingOccurrences(of: "=", with: ""), key: pub)),
    ("con salto de línea final rechazada", !accepts(goodBody, sig: good + "\n", key: pub)),
    ("con espacio inicial rechazada", !accepts(goodBody, sig: " " + good, key: pub)),
    ("alfabeto URL-safe rechazada (si aplica)", urlSafe == good || !accepts(goodBody, sig: urlSafe, key: pub)),
    ("control posterior aceptado", accepts(goodBody, sig: good, key: pub))
], bad: reply(goodBody, sig: nonCanon), obs: [
    "el decodificador de Foundation \(Data(base64Encoded: nonCanon) == raw ? "ES" : "NO es") permisivo con bits de relleno"
])

await p3("P3-3", "Content-Type incorrecto", [
    ("text/plain rechazado", !accepts(goodBody, sig: good, ct: "text/plain", key: pub)),
    ("application/jsonx rechazado", !accepts(goodBody, sig: good, ct: "application/jsonx", key: pub)),
    ("text/html rechazado", !accepts(goodBody, sig: good, ct: "text/html", key: pub)),
    ("sin Content-Type rechazado", !accepts(goodBody, sig: good, ct: nil, key: pub)),
    ("control posterior aceptado", accepts(goodBody, sig: good, key: pub))
], bad: reply(goodBody, sig: good, ct: "text/plain"), obs: [
    "'application/json; charset=utf-8' → \(accepts(goodBody, sig: good, ct: "application/json; charset=utf-8", key: pub) ? "aceptado" : "RECHAZADO (falla cerrada; un gateway con charset quedaría mudo)")"
])

await p3("P3-4", "encabezado de firma ausente", [
    ("sin encabezado rechazado", !accepts(goodBody, sig: nil, key: pub)),
    ("encabezado vacío rechazado", !accepts(goodBody, sig: "", key: pub)),
    ("control posterior aceptado", accepts(goodBody, sig: good, key: pub))
], bad: reply(goodBody, sig: nil))

let otherSig = sign(goodBody, attacker)
await p3("P3-5", "clave pública distinta de la configurada", [
    ("firmado por atacante, verificado con clave configurada: rechazado", !accepts(goodBody, sig: otherSig, key: pub)),
    ("firmado por la configurada, verificado con otra clave: rechazado", !accepts(goodBody, sig: good, key: attacker.publicKey)),
    ("control con la clave correcta aceptado", accepts(goodBody, sig: good, key: pub))
], bad: reply(goodBody, sig: otherSig))

var noPrefix = Data()
noPrefix.append(goodBody)
let sigNoPrefix = try! priv.signature(for: noPrefix).base64EncodedString()
await p3("P3-6", "cuerpo sin el prefijo canónico JDB-1\\n", [
    ("firma sobre cuerpo sin prefijo rechazada", !accepts(goodBody, sig: sigNoPrefix, key: pub)),
    ("prefijo JDB-2\\n rechazado", !accepts(goodBody, sig: sign(goodBody, priv, prefix: "JDB-2\n"), key: pub)),
    ("prefijo JDB-1 sin salto rechazado", !accepts(goodBody, sig: sign(goodBody, priv, prefix: "JDB-1"), key: pub)),
    ("prefijo en minúsculas rechazado", !accepts(goodBody, sig: sign(goodBody, priv, prefix: "jdb-1\n"), key: pub)),
    ("control posterior aceptado", accepts(goodBody, sig: good, key: pub))
], bad: reply(goodBody, sig: sigNoPrefix))

// ───────── PUNTO 4 — FRESCURA Y REPLAY ─────────

func delivery(_ b: Data) -> Stub.Reply { reply(b, sig: sign(b, priv)) }

let blockMsg = e2eBlock

// P4-1: command_id repetido tras reinicio
if blockMsg == nil {
    resetState()
    let id = UUID().uuidString.lowercased()
    let b1 = commandBody(id: id, text: "nota p4-1", issued: n - 10, expires: n + 100)
    let fp = SignedDelivery.digest(b1)
    _ = await e2e([delivery(b1)], waitTasks: 1, timeout: 8, settle: 1.0)
    var c: [(String, Bool)] = [
        ("control: 1.ª entrega ejecutada (nota creada)", noteExists(id)),
        ("diario persistido con fingerprint", journal()?.commands[id]?.fingerprint == fp)
    ]
    noteDelete(id)
    Stub.reset()
    _ = await e2e([delivery(b1)], waitTasks: 1, timeout: 8, settle: 1.0) // app reiniciada
    c += [
        ("reinicio: NO se re-ejecuta (nota no recreada)", !noteExists(id)),
        ("reinicio: diario sobrevive y conserva fingerprint", journal()?.commands[id]?.fingerprint == fp)
    ]
    let acks2 = Stub.posts("/ack").count, res2 = Stub.posts("/result").count
    Stub.reset()
    let b2 = commandBody(id: id, text: "OTRO TEXTO", issued: n - 10, expires: n + 100)
    let st3 = await e2e([delivery(b2)], waitTasks: 1, timeout: 8, settle: 0.8)
    c += [
        ("mismo command_id con cuerpo distinto (bien firmado): rechazado sin ACK/result", Stub.posts("/ack").isEmpty && Stub.posts("/result").isEmpty),
        ("…y sin ejecutar", !noteExists(id)),
        ("…y diario intacto", journal()?.commands[id]?.fingerprint == fp),
        ("…y estado de error = \(st3)", st3 == "Error de sondeo o entrega")
    ]
    report("P4-1", "command_id repetido con diario persistido tras reinicio", c, obs: [
        "replay idéntico tras reinicio: ACK reenviado \(acks2), result en caché reenviado \(res2) (idempotente, no es rechazo)"
    ])
} else {
    report("P4-1", "command_id repetido tras reinicio", [], blocked: blockMsg)
}

// P4-2: comando expirado
do {
    let b = commandBody(issued: n - 100, expires: n - 10)
    let id = (try! JSONDecoder().decode(Command.self, from: b)).command_id
    var c: [(String, Bool)] = [
        ("validate(estricto) lo rechaza", !validates(b, at: nowD)),
        ("control: vigente validado", validates(commandBody(issued: n - 10, expires: n + 100), at: nowD))
    ]
    var o = ["validate(allowExpired:true) → \(validates(b, at: nowD, allowExpired: true) ? "ACEPTA (run() usa este modo)" : "rechaza")"]
    if e2eBlock == nil {
        resetState()
        _ = await e2e([delivery(b)], waitTasks: 1, timeout: 6, settle: 1.0)
        c.append(("e2e: NO se ejecuta (sin nota)", !noteExists(id)))
        if let r = Stub.posts("/result").first, let cr = try? JSONDecoder().decode(CommandResult.self, from: r) {
            c.append(("e2e: si hay result, status ≠ ok (\(cr.status))", cr.status != "ok"))
        }
        o.append("e2e: ACK= \(Stub.posts("/ack").count) result= \(Stub.posts("/result").count)")
    } else {
        o.append("e2e no ejecutado: \(e2eBlock!)")
    }
    report("P4-2", "comando expirado", c, obs: o)
}

// P4-3 / P4-4 comunes
@MainActor func e2eNoEffect(_ b: Data) async -> [(String, Bool)] {
    resetState()
    let id = (try! JSONDecoder().decode(Command.self, from: b)).command_id
    let st = await e2e([delivery(b)], waitTasks: 1, timeout: 6, settle: 0.8)
    return [
        ("e2e: sin ACK ni result", Stub.posts("/ack").isEmpty && Stub.posts("/result").isEmpty),
        ("e2e: sin ejecución", !noteExists(id)),
        ("e2e: sin entrada en diario", journal()?.commands[id] == nil),
        ("e2e: estado de error = \(st)", st == "Error de sondeo o entrega")
    ]
}

do {
    let big = commandBody(issued: n - 10, expires: n + 200)
    let b121 = commandBody(issued: n - 10, expires: n + 111)
    var c: [(String, Bool)] = [
        ("TTL 210 s rechazado (estricto)", !validates(big, at: nowD)),
        ("TTL 210 s rechazado (allowExpired)", !validates(big, at: nowD, allowExpired: true)),
        ("TTL 121 s rechazado", !validates(b121, at: nowD)),
        ("control: TTL 120 s aceptado", validates(commandBody(issued: n - 10, expires: n + 110), at: nowD))
    ]
    var o: [String] = []
    if e2eBlock == nil { c += await e2eNoEffect(big) } else { o.append("e2e no ejecutado: \(e2eBlock!)") }
    report("P4-3", "TTL mayor de 120 s", c, obs: o)
}

do {
    let fut = commandBody(issued: n + 300, expires: n + 360)
    let near = commandBody(issued: n + 5, expires: n + 65)
    var c: [(String, Bool)] = [
        ("issued_at +300 s rechazado (estricto)", !validates(fut, at: nowD)),
        ("issued_at +300 s rechazado (allowExpired)", !validates(fut, at: nowD, allowExpired: true)),
        ("control: issued_at = ahora aceptado", validates(commandBody(issued: n, expires: n + 60), at: nowD))
    ]
    var o = ["tolerancia de skew efectiva: \(validates(near, at: nowD) ? "≥5 s" : "0 s (issued_at +5 s ya se rechaza)")"]
    if e2eBlock == nil { c += await e2eNoEffect(fut) } else { o.append("e2e no ejecutado: \(e2eBlock!)") }
    report("P4-4", "issued_at en el futuro fuera de skew", c, obs: o)
}

// P4-5: replay íntegro dentro de la misma sesión
if blockMsg == nil {
    resetState()
    let id = UUID().uuidString.lowercased()
    let b = commandBody(id: id, text: "nota p4-5", issued: n - 10, expires: n + 100)
    let d = delivery(b)
    var seenBefore = false
    Stub.onTask = { k in
        if k == 2 { seenBefore = noteExists(id); noteDelete(id) }
    }
    _ = await e2e([d, d], waitTasks: 2, timeout: 15, settle: 1.0)
    let c: [(String, Bool)] = [
        ("control: 1.ª entrega ejecutada", seenBefore),
        ("replay íntegro: NO se re-ejecuta (nota no recreada)", !noteExists(id)),
        ("diario conserva fingerprint", journal()?.commands[id]?.fingerprint == SignedDelivery.digest(b))
    ]
    report("P4-5", "sobre válido capturado y reenviado tal cual", c, obs: [
        "ACK= \(Stub.posts("/ack").count) result= \(Stub.posts("/result").count) (reenvío idempotente del resultado en caché; no es rechazo)"
    ])
} else {
    report("P4-5", "replay íntegro", [], blocked: blockMsg)
}

print("== RESUMEN: PASS= \(tally["PASS"]!) FAIL= \(tally["FAIL"]!) BLOCKED= \(tally["BLOCKED"]!) ==")
exit(tally["FAIL"]! == 0 && tally["BLOCKED"]! == 0 ? 0 : 1)
