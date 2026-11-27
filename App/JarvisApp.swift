import Foundation
import SwiftUI

@main
@MainActor
struct JarvisApp: App {
    var body: some Scene {
        WindowGroup { StatusView() }
    }
}

@MainActor
struct StatusView: View {
    @StateObject private var agent = Agent()
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("gatewayURL") private var address = ""
    @State private var credential = ""
    @State private var signingKey = ""
    @State private var credentialStatus = ""
    @State private var enabled = false

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Dispositivo")) {
                    Text(Credential.device)
                    Text(enabled && scenePhase == .active ? agent.status : "Sondeo detenido")
                }
                Section(header: Text("Gateway")) {
                    TextField("URL HTTPS del gateway", text: $address)
                        .keyboardType(.URL)
                        .textContentType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(enabled)
                    SecureField("Credencial del dispositivo", text: $credential)
                        .textInputAutocapitalization(.never)
                        .disabled(enabled)
                    Button("Guardar credencial") {
                        defer { credential = "" }
                        do {
                            try Credential.save(credential)
                            credentialStatus = "Credencial guardada en Keychain"
                        } catch {
                            credentialStatus = "Error al guardar la credencial"
                        }
                    }
                    .disabled(enabled || credential.isEmpty)
                    TextField("Ed25519 public key (Base64)", text: $signingKey)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(enabled)
                    Button("Guardar clave p?blica") {
                        defer { signingKey = "" }
                        guard let key = Data(base64Encoded: signingKey), key.count == 32 else {
                            credentialStatus = "La clave debe contener 32 bytes en Base64"
                            return
                        }
                        do {
                            try Credential.save(signingKey, service: Credential.signingService)
                            credentialStatus = "Clave p?blica guardada en Keychain"
                        } catch {
                            credentialStatus = "Error al guardar la clave"
                        }
                    }
                    .disabled(enabled || signingKey.isEmpty)
                    if !credentialStatus.isEmpty { Text(credentialStatus) }
                    Toggle("Sondear gateway", isOn: $enabled)
                        .disabled(address.isEmpty)
                }
            }
            .navigationTitle("JARVIS Device Agent")
        }
        .navigationViewStyle(.stack)
        .task(id: enabled && scenePhase == .active) {
            if enabled && scenePhase == .active {
                await agent.run(address: address)
                if !Task.isCancelled { enabled = false }
            }
        }
    }
}
