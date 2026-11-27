"""Run the production CryptoKit verifier against the shared fixtures."""
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent
swift = shutil.which("swift")
if swift is None:
    raise SystemExit("Swift with CryptoKit is required (run on macOS).")

source = (root / "Agent.swift").read_text(encoding="utf-8")
verifier = source[source.index("enum DeliverySignature {"):source.index("struct SignedDelivery {")]
runner = """
struct Vector: Decodable {
    let name: String
    let body: Data
    let signature: String
    let valid: Bool
}
struct Suite: Decodable {
    let public_key: Data
    let cases: [Vector]
}
let input = URL(fileURLWithPath: CommandLine.arguments[1])
let suite = try JSONDecoder().decode(Suite.self, from: Data(contentsOf: input))
let key = try Curve25519.Signing.PublicKey(rawRepresentation: suite.public_key)
for vector in suite.cases {
    precondition(DeliverySignature.verifies(vector.signature, body: vector.body, key: key)
                 == vector.valid, vector.name)
    print("PASS", vector.name)
}
"""

with tempfile.TemporaryDirectory(dir=root) as folder:
    script = Path(folder) / "Vectors.swift"
    script.write_text("import Foundation\nimport CryptoKit\n" + verifier + runner, encoding="utf-8")
    subprocess.run([swift, str(script), str(root / "jdb1-ed25519-vectors.json")],
                   cwd=root, check=True)
