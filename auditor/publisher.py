#!/usr/bin/env python3
"""Narrow publisher: consumes audited envelopes, updates this repo, signs index."""

from __future__ import annotations
import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import subprocess
import tempfile
import tomllib
from github_app import github_json, installation_token
from validation import (
    MANUAL_APPROVERS, submission_id, submission_kind, validate_manifest_identity,
    validate_publishable_audit, validate_submission,
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, **kwargs)


def git(repo: pathlib.Path, args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args], **kwargs)


def private_file(path: pathlib.Path, label: str) -> pathlib.Path:
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError(f"{label} must be a mode-600 private file")
    return path


def push_with_token(repo: pathlib.Path, repository: str, token: str) -> None:
    with tempfile.TemporaryDirectory(prefix="tine-plugin-publisher-") as temp:
        askpass = pathlib.Path(temp) / "askpass.sh"
        askpass.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
            "  *) printf '%s\\n' \"$TINE_GITHUB_TOKEN\" ;;\n"
            "esac\n"
        )
        askpass.chmod(0o700)
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/nonexistent",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": str(askpass),
            "TINE_GITHUB_TOKEN": token,
        }
        run(
            [
                "git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
                "-C", str(repo), "push", f"https://github.com/{repository}.git", "HEAD:main",
            ],
            env=env,
        )


def quarantine_comment(envelope: dict, disposition: str) -> str:
    checker = envelope.get("checker", {})
    ai = envelope.get("aiReview", {})
    lines = [
        f"Automated audit result: **{disposition}**.",
        "",
        f"- Deterministic checks: `{checker.get('status', 'unknown')}`",
        f"- Capability risk: `{checker.get('risk', 'unknown')}`",
        f"- AI source review: `{ai.get('disposition', 'unknown')}` (uncertain: `{bool(ai.get('uncertain', True))}`)",
    ]
    findings = ai.get("findings", []) if isinstance(ai, dict) else []
    if findings:
        lines.extend(["", "Review findings:"])
        for finding in findings[:10]:
            if isinstance(finding, dict):
                lines.append(f"- **{finding.get('severity', 'unknown')}** — {finding.get('title', 'Untitled finding')}")
    lines.extend(["", "No code was published. A maintainer can review the quarantined envelope locally."])
    return "\n".join(lines)


def publish(
    envelope_path: pathlib.Path,
    repo: pathlib.Path,
    key: pathlib.Path,
    approve_quarantine: bool = False,
    approval_note: str = "",
    approved_by: str = MANUAL_APPROVERS[0],
) -> tuple[str, str, int | None]:
    envelope = json.loads(envelope_path.read_text())
    pr = envelope.get("pullRequest", {}).get("number")
    disposition = envelope.get("disposition", "quarantine")
    if approve_quarantine and disposition == "quarantine":
        if approved_by not in MANUAL_APPROVERS:
            raise RuntimeError("unknown manual approver")
        checker = envelope.get("checker", {})
        ai = envelope.get("aiReview", {})
        if checker.get("status") != "passed" or ai.get("disposition") != "pass" or ai.get("uncertain"):
            raise RuntimeError("manual approval requires deterministic pass and certain AI pass")
        existing_approval = envelope.get("manualApproval")
        if existing_approval is not None:
            if (
                not isinstance(existing_approval, dict)
                or existing_approval.get("by") != approved_by
                or existing_approval.get("note") != approval_note
                or not isinstance(existing_approval.get("approvedAt"), str)
            ):
                raise RuntimeError("stored manual approval does not match this approval request")
        else:
            envelope["manualApproval"] = {
                "by": approved_by,
                "note": approval_note,
                "approvedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            # Persist the approval identity/timestamp before any network action so
            # a failed push can be retried without changing immutable audit bytes.
            envelope_path.write_bytes(canonical(envelope))
        disposition = "publish"
    if disposition != "publish":
        return disposition, quarantine_comment(envelope, disposition), pr
    submission = validate_submission(envelope["submission"])
    validate_publishable_audit(envelope, submission)
    package = envelope["package"]
    kind, pid, version = submission_kind(submission), submission_id(submission), submission["version"]
    manifest = validate_manifest_identity(package["manifest"], submission)
    manifest_bytes = canonical(manifest)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if package.get("manifestSha256") != manifest_sha256:
        raise RuntimeError("audited manifest digest does not match package bytes")
    package_dir = repo / ("packages" if kind == "plugin" else "themes") / pid / version
    audit_dir = repo / "audits" / pid
    package_dir.mkdir(parents=True, exist_ok=True); audit_dir.mkdir(parents=True, exist_ok=True)
    wasm = b""
    wasm_sha256 = ""
    if kind == "plugin":
        wasm = base64.b64decode(package["wasmBase64"], validate=True)
        wasm_sha256 = hashlib.sha256(wasm).hexdigest()
        if package.get("sha256") != wasm_sha256:
            raise RuntimeError("audited WASM digest does not match package bytes")
    public_audit = {key: value for key, value in envelope.items() if key != "package"}
    audit_bytes = canonical(public_audit)
    audit_sha256 = hashlib.sha256(audit_bytes).hexdigest()
    files = {audit_dir / f"{version}.json": audit_bytes}
    if kind == "plugin":
        files[package_dir / "manifest.json"] = manifest_bytes
        files[package_dir / "plugin.wasm"] = wasm
    else:
        files[package_dir / "theme.json"] = manifest_bytes
    for path, data in files.items():
        if path.exists() and path.read_bytes() != data:
            raise RuntimeError(f"immutable registry artifact differs: {path}")
        path.write_bytes(data)
    index_path = repo / "index.json"
    index = json.loads(index_path.read_text())
    collection_name = "plugins" if kind == "plugin" else "themes"
    collection = {item["id"]: item for item in index.get(collection_name, [])}
    item = collection.setdefault(pid, {
        "id": pid, "name": manifest["name"], "description": manifest["description"],
        "source": manifest["source"], "license": manifest["license"],
        "aiDevelopment": manifest.get("aiDevelopment", "none"), "versions": [],
    })
    is_new_version = not any(candidate["version"] == version for candidate in item["versions"])
    if is_new_version:
        base = f"https://raw.githubusercontent.com/martinkoutecky/tine-plugin-registry/main"
        version_entry = {
            "version": version, "apiVersion": manifest["apiVersion"],
            "manifestSha256": manifest_sha256,
            "manifestUrl": f"{base}/{'packages' if kind == 'plugin' else 'themes'}/{pid}/{version}/{'manifest.json' if kind == 'plugin' else 'theme.json'}",
            "audit": {
                "status": "passed",
                "url": f"{base}/audits/{pid}/{version}.json",
                "sha256": audit_sha256,
                "risk": envelope["checker"]["risk"],
                "automatedDisposition": envelope["disposition"],
                "manualApproval": "manualApproval" in envelope,
                "checkedAt": envelope["checker"]["checkedAt"],
            },
            "publishedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        if kind == "plugin":
            version_entry.update({
                "platforms": manifest.get("platforms", ["desktop"]),
                "capabilities": manifest["capabilities"],
                "sha256": wasm_sha256,
                "wasmUrl": f"{base}/packages/{pid}/{version}/plugin.wasm",
            })
        else:
            version_entry["modes"] = sorted(manifest["modes"].keys())
        item["versions"].append(version_entry)
    # Catalogue metadata follows the most recently published version. Replaying
    # an older immutable audit must not roll the public listing back.
    if is_new_version or item["versions"][-1]["version"] == version:
        item.update({
            "name": manifest["name"],
            "description": manifest["description"],
            "source": manifest["source"],
            "license": manifest["license"],
            "aiDevelopment": manifest.get("aiDevelopment", "none"),
        })
    index[collection_name] = sorted(collection.values(), key=lambda candidate: candidate["id"])
    index.setdefault("plugins", [])
    index.setdefault("themes", [])
    index["generatedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    index_bytes = canonical(index)
    index_path.write_bytes(index_bytes)
    raw_signature = repo / ".index.sig.raw"
    run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(index_path), "-out", str(raw_signature)])
    (repo / "index.json.sig").write_text(base64.b64encode(raw_signature.read_bytes()).decode() + "\n")
    raw_signature.unlink()
    return "published", f"Automated checks passed and {kind} {pid}@{version} was published.", pr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("envelope", type=pathlib.Path)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--approve-quarantine", action="store_true")
    parser.add_argument("--approval-note", default="")
    parser.add_argument("--approved-by", choices=MANUAL_APPROVERS, help="required with --approve-quarantine")
    args = parser.parse_args()
    if args.approve_quarantine and not args.approved_by:
        parser.error("--approve-quarantine requires --approved-by")
    config = tomllib.loads(args.config.read_text())
    repo = pathlib.Path(config["registry_checkout"])
    key = private_file(pathlib.Path(config["signing_key"]), "registry signing key")
    disposition, comment, pr = publish(
        args.envelope,
        repo,
        key,
        approve_quarantine=args.approve_quarantine,
        approval_note=args.approval_note,
        approved_by=args.approved_by or MANUAL_APPROVERS[0],
    )
    if disposition == "published":
        git(repo, ["add", "index.json", "index.json.sig", "packages", "themes", "audits"])
        if subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), "diff", "--cached", "--quiet"]
        ).returncode != 0:
            git(repo, ["commit", "-m", "registry: publish audited submission"])
        app_key = private_file(pathlib.Path(config["github_app_private_key"]), "GitHub App private key")
        token = installation_token(int(config["github_app_id"]), int(config["github_installation_id"]), app_key)
        push_with_token(repo, config["registry"], token)
    if pr is not None:
        if disposition != "published":
            app_key = private_file(pathlib.Path(config["github_app_private_key"]), "GitHub App private key")
            token = installation_token(int(config["github_app_id"]), int(config["github_installation_id"]), app_key)
        github_json(
            f"https://api.github.com/repos/{config['registry']}/issues/{pr}/comments",
            "POST",
            token,
            {"body": comment},
        )


if __name__ == "__main__":
    main()
