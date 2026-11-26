"""Offline reference vectors for the JDB-1 development delivery profile."""

import base64
import hashlib
import hmac
import json
import re
import unittest
import uuid


KEY = bytes(range(32))  # Published fixture, never provision on deployed devices.
NOW = 1795708800
KEY_ID = "gateway-dev"
REQUEST_ID = "b" * 32
BODY = {
    "protocol": "JDB-1",
    "device_id": "JARVIS-IP8-001",
    "command_id": "4c420e7e-a216-4ef0-ba63-034d5c9c5ee1",
    "origin": "codex",
    "capability": "GET_BATTERY",
    "issued_at": NOW - 10,
    "expires_at": NOW + 110,
    "requires_approval": False,
    "payload": {},
}


def encode(command):
    return json.dumps(command, separators=(",", ":")).encode()


def digest(body):
    return hashlib.sha256(body).hexdigest()


def signature(body, key_id, timestamp, nonce, request_id, method, path):
    canonical = "\n".join(
        ("JARVIS-HMAC-V1", key_id, timestamp, nonce, request_id, method, path, digest(body))
    )
    tag = hmac.digest(KEY, canonical.encode(), "sha256")
    return base64.urlsafe_b64encode(tag).decode().rstrip("=")


def sign_delivery(body, nonce, timestamp=str(NOW)):
    return signature(body, KEY_ID, timestamp, nonce, REQUEST_ID, "GET", "/task")


class ReferencePhone:
    def __init__(self, journal=None):
        self.journal = {"nonces": {}, "commands": {}} if journal is None else json.loads(journal)
        self.executions = 0

    def receive(self, body, nonce, tag, *, timestamp=str(NOW), request_id=REQUEST_ID,
                key_id=KEY_ID, content_type="application/json"):
        if not (
            key_id == KEY_ID
            and re.fullmatch(r"[1-9][0-9]{0,18}", timestamp)
            and abs(NOW - int(timestamp)) <= 60
            and re.fullmatch(r"[0-9a-f]{32}", nonce)
            and re.fullmatch(r"[0-9a-f]{32}", request_id)
            and re.fullmatch(r"[A-Za-z0-9_-]{43}", tag)
            and content_type.lower() == "application/json"
            and len(body) <= 512
            and hmac.compare_digest(
                tag, signature(body, key_id, timestamp, nonce, request_id, "GET", "/task")
            )
        ):
            return "rejected_signature_or_headers"
        nonces = self.journal["nonces"]
        if nonces.get(nonce, 0) > NOW:
            return "replayed_nonce"
        self.journal["nonces"] = {n: expiry for n, expiry in nonces.items() if expiry > NOW}
        self.journal["nonces"][nonce] = NOW + 180
        command = json.loads(body)
        command_id = command["command_id"].lower()
        issued = command["issued_at"]
        expires = command["expires_at"]
        if not (
            command["protocol"] == "JDB-1"
            and command["device_id"] == "JARVIS-IP8-001"
            and str(uuid.UUID(command_id)) == command_id
            and command["origin"] in {"maus", "alpha", "beta", "codex"}
            and command["capability"] in {"GET_STATUS", "GET_BATTERY", "GET_NETWORK"}
            and command["requires_approval"] is False
            and command["payload"] == {}
            and type(issued) is int and type(expires) is int
            and 0 < issued <= NOW < expires <= issued + 120
        ):
            return "rejected_envelope"
        commands = self.journal["commands"]
        if command_id in commands:
            return "cached" if commands[command_id] == digest(body) else "conflict"
        commands[command_id] = digest(body)
        self.executions += 1
        return "executed"


class Vectors(unittest.TestCase):
    def setUp(self):
        self.phone = ReferencePhone()
        self.body = encode(BODY)
        self.nonce = "a" * 32
        self.tag = sign_delivery(self.body, self.nonce)

    def test_published_v1(self):
        body = b'{"task":"JARVIS-LAB","nonce":"0123456789abcdef0123456789abcdef","text":"HOLA"}'
        self.assertEqual(digest(body), "e1c05c4fec69c3d5d80fbf1e4f52a42cf42e126e5c267772b6d58efeb4c432be")
        self.assertEqual(
            signature(body, "kid-test-01", str(NOW), self.nonce, REQUEST_ID, "POST", "/result"),
            "LHM0KjLHsANjM5dONihxOdY3oF7MpOrYFM9cLSuzR6o",
        )

    def test_valid_signature_executes(self):
        self.assertEqual(self.phone.receive(self.body, self.nonce, self.tag), "executed")
        self.assertEqual(self.phone.executions, 1)

    def test_invalid_signature_rejected(self):
        bad_tag = ("A" if self.tag[0] != "A" else "B") + self.tag[1:]
        self.assertEqual(self.phone.receive(self.body, self.nonce, bad_tag), "rejected_signature_or_headers")
        self.assertEqual(self.phone.executions, 0)

    def test_expired_at_boundary_rejected_with_fresh_signature(self):
        body = encode(dict(BODY, expires_at=NOW))
        self.assertEqual(self.phone.receive(body, self.nonce, sign_delivery(body, self.nonce)), "rejected_envelope")
        self.assertEqual(self.phone.executions, 0)

    def test_duplicate_command_after_journal_reload(self):
        self.assertEqual(self.phone.receive(self.body, self.nonce, self.tag), "executed")
        restarted = ReferencePhone(json.dumps(self.phone.journal))
        fresh_nonce = "c" * 32
        self.assertEqual(restarted.receive(self.body, self.nonce, self.tag), "replayed_nonce")
        self.assertEqual(restarted.receive(self.body, fresh_nonce, sign_delivery(self.body, fresh_nonce)), "cached")
        self.assertEqual(restarted.executions, 0)

    def test_tampered_body_rejected(self):
        body = encode(dict(BODY, capability="GET_NETWORK"))
        self.assertEqual(self.phone.receive(body, self.nonce, self.tag), "rejected_signature_or_headers")
        self.assertEqual(self.phone.executions, 0)

    def test_changed_body_with_same_command_id_conflicts(self):
        self.assertEqual(self.phone.receive(self.body, self.nonce, self.tag), "executed")
        body = encode(dict(BODY, capability="GET_NETWORK"))
        fresh_nonce = "c" * 32
        self.assertEqual(self.phone.receive(body, fresh_nonce, sign_delivery(body, fresh_nonce)), "conflict")
        self.assertEqual(self.phone.executions, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
