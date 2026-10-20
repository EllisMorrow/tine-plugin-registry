import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

from publisher import canonical, private_file, publish


def envelope(plugin_id="page.tine.example"):
    manifest = {
        "schemaVersion": 1,
        "id": plugin_id,
        "name": "Example",
        "version": "0.1.0",
        "apiVersion": "0.2",
        "description": "Example plugin",
        "author": "Example",
        "license": "MIT",
        "source": "https://github.com/example/plugin",
        "entry": "plugin.wasm",
        "platforms": ["desktop"],
        "capabilities": [],
    }
    wasm = b"\0asm\x01\0\0\0"
    return {
        "format": "tine-plugin-audit-result/v1",
        "disposition": "publish",
        "commitVerified": "a" * 40,
        "submission": {
            "schemaVersion": 1,
            "pluginId": plugin_id,
            "version": "0.1.0",
            "repository": "https://github.com/example/plugin",
            "commit": "a" * 40,
            "manifestPath": "manifest.json",
        },
        "checker": {"status": "passed", "risk": "low", "checkedAt": "2026-07-11T00:00:00Z"},
        "aiReview": {
            "disposition": "pass",
            "uncertain": False,
            "summary": "No security-relevant behavior found.",
            "findings": [],
            "areasReviewed": ["manifest and guest imports"],
        },
        "package": {
            "manifest": manifest,
            "manifestSha256": hashlib.sha256(canonical(manifest)).hexdigest(),
            "wasmBase64": base64.b64encode(wasm).decode(),
            "sha256": hashlib.sha256(wasm).hexdigest(),
        },
    }


class PublisherSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.repo = self.root / "registry"
        self.repo.mkdir()
        (self.repo / "index.json").write_text(
            json.dumps({"schemaVersion": 1, "generatedAt": "initial", "plugins": [], "themes": [], "revocations": []}) + "\n"
        )
        self.key = self.root / "key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.key)], check=True)

    def tearDown(self):
        self.temp.cleanup()

    def write_envelope(self, value):
        path = self.root / "envelope.json"
        path.write_text(json.dumps(value))
        return path

    def test_publisher_recomputes_and_pins_both_artifact_digests(self):
        result = publish(self.write_envelope(envelope()), self.repo, self.key)
        self.assertEqual(result[0], "published")
        index = json.loads((self.repo / "index.json").read_text())
        version = index["plugins"][0]["versions"][0]
        self.assertRegex(version["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(version["manifestSha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(version["audit"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(version["audit"]["risk"], "low")
        self.assertFalse(version["audit"]["manualApproval"])

    def test_local_publish_lifecycle_produces_a_verifiable_signed_index(self):
        self.key.chmod(0o600)
        self.assertEqual(publish(self.write_envelope(envelope()), self.repo, self.key)[0], "published")
        public_key = self.root / "key.pub.pem"
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.key), "-pubout", "-out", str(public_key)],
            check=True,
        )
        signature = self.root / "signature.raw"
        signature.write_bytes(base64.b64decode((self.repo / "index.json.sig").read_text().strip(), validate=True))
        subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
                "-rawin", "-in", str(self.repo / "index.json"), "-sigfile", str(signature),
            ],
            check=True,
        )

    def test_publisher_rejects_traversal_and_tampered_bytes_before_writing(self):
        bad_path = envelope("../../outside")
        with self.assertRaises(ValueError):
            publish(self.write_envelope(bad_path), self.repo, self.key)
        self.assertFalse((self.root / "outside").exists())

        bad_digest = envelope()
        bad_digest["package"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "WASM digest"):
            publish(self.write_envelope(bad_digest), self.repo, self.key)

    def test_publisher_rejects_a_report_tine_cannot_verify(self):
        bad_commit = envelope()
        bad_commit["commitVerified"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "verified source commit"):
            publish(self.write_envelope(bad_commit), self.repo, self.key)

        missing_evidence = envelope()
        del missing_evidence["aiReview"]["areasReviewed"]
        with self.assertRaisesRegex(ValueError, "review areas"):
            publish(self.write_envelope(missing_evidence), self.repo, self.key)

    def test_private_credentials_must_not_be_group_or_world_readable(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "mode-600"):
            private_file(self.key, "test key")
        self.key.chmod(0o600)
        self.assertEqual(private_file(self.key, "test key"), self.key)

    def test_publisher_writes_inert_theme_without_executable_artifact(self):
        manifest = {
            "schemaVersion": 1, "id": "org.tine.theme.example", "name": "Example colors",
            "version": "1.0.0", "apiVersion": "0.1", "description": "Example theme",
            "author": "Example", "license": "MIT", "source": "https://github.com/example/theme",
            "modes": {"dark": {"--ls-primary-background-color": "#111111"}},
            "screenshots": [], "aiDevelopment": "none",
        }
        submission = {
            "schemaVersion": 2, "kind": "theme", "packageId": manifest["id"],
            "version": manifest["version"], "repository": manifest["source"],
            "commit": "c" * 40, "manifestPath": "theme.json",
        }
        value = {
            "format": "tine-package-audit-result/v1", "disposition": "publish",
            "commitVerified": submission["commit"], "submission": submission,
            "checker": {"status": "passed", "risk": "low", "checkedAt": "2026-07-12T00:00:00Z"},
            "aiReview": {"disposition": "pass", "uncertain": False, "summary": "Inert colors only.",
                         "findings": [], "areasReviewed": ["theme manifest and provenance"]},
            "package": {"manifest": manifest, "manifestSha256": hashlib.sha256(canonical(manifest)).hexdigest()},
        }
        result = publish(self.write_envelope(value), self.repo, self.key)
        self.assertEqual(result[0], "published")
        index = json.loads((self.repo / "index.json").read_text())
        version = index["themes"][0]["versions"][0]
        self.assertEqual(version["modes"], ["dark"])
        self.assertNotIn("wasmUrl", version)
        self.assertTrue((self.repo / "themes" / manifest["id"] / "1.0.0" / "theme.json").is_file())

    def test_newest_publication_refreshes_catalogue_metadata_without_old_replay_rollback(self):
        first = envelope()
        first_path = self.write_envelope(first)
        publish(first_path, self.repo, self.key)

        second = envelope()
        second["submission"]["version"] = "0.2.0"
        second["submission"]["commit"] = "b" * 40
        second["commitVerified"] = "b" * 40
        second["package"]["manifest"]["version"] = "0.2.0"
        second["package"]["manifest"]["name"] = "Renamed example"
        second["package"]["manifest"]["description"] = "Expanded example"
        second["package"]["manifestSha256"] = hashlib.sha256(
            canonical(second["package"]["manifest"])
        ).hexdigest()
        publish(self.write_envelope(second), self.repo, self.key)

        item = json.loads((self.repo / "index.json").read_text())["plugins"][0]
        self.assertEqual(item["name"], "Renamed example")
        self.assertEqual(item["description"], "Expanded example")

        publish(first_path, self.repo, self.key)
        item = json.loads((self.repo / "index.json").read_text())["plugins"][0]
        self.assertEqual(item["name"], "Renamed example")
        self.assertEqual(item["description"], "Expanded example")

    def test_manual_approval_is_persisted_for_idempotent_push_retries(self):
        value = envelope()
        value["disposition"] = "quarantine"
        path = self.write_envelope(value)
        publish(path, self.repo, self.key, approve_quarantine=True, approval_note="reviewed")
        first = json.loads(path.read_text())["manualApproval"]
        publish(path, self.repo, self.key, approve_quarantine=True, approval_note="reviewed")
        self.assertEqual(json.loads(path.read_text())["manualApproval"], first)

    def test_manual_approval_records_the_named_approver(self):
        value = envelope()
        value["disposition"] = "quarantine"
        path = self.write_envelope(value)
        publish(path, self.repo, self.key, approve_quarantine=True, approval_note="reviewed",
                approved_by="Claude (working on Martin's behalf)")
        self.assertEqual(json.loads(path.read_text())["manualApproval"]["by"], "Claude (working on Martin's behalf)")
        # A retry by a different approver must not rewrite the stored, immutable approval.
        with self.assertRaises(RuntimeError):
            publish(path, self.repo, self.key, approve_quarantine=True, approval_note="reviewed")

    def test_manual_approval_rejects_an_unknown_approver(self):
        value = envelope()
        value["disposition"] = "quarantine"
        path = self.write_envelope(value)
        with self.assertRaises(RuntimeError):
            publish(path, self.repo, self.key, approve_quarantine=True, approval_note="reviewed", approved_by="Mallory")
        self.assertNotIn("manualApproval", json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
