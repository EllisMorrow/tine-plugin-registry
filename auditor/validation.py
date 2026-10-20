"""Small, dependency-free trust-boundary validators shared by auditor/publisher."""

from __future__ import annotations
import pathlib
import re

# Who may approve a quarantined version (POLICY.md: "a named manual approval").
# Each acts on Martin's explicit authority for that package; the name is recorded.
MANUAL_APPROVERS = (
    "Sol (working on Martin's behalf)",
    "Claude (working on Martin's behalf)",
)

ID = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{1,62}[a-z0-9])$")
VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
REPOSITORY = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SUBMISSION_V1_FIELDS = {"schemaVersion", "pluginId", "version", "repository", "commit", "manifestPath"}
SUBMISSION_V2_FIELDS = {"schemaVersion", "kind", "packageId", "version", "repository", "commit", "manifestPath"}
AUDIT_RISKS = {"low", "review", "elevated"}
FINDING_SEVERITIES = {"info", "low", "medium", "high", "critical"}
# A named approver may accept findings up to this severity by title; a high or
# critical finding, or a rejecting review, can never be approved past.
ACCEPTABLE_SEVERITIES = {"info", "low", "medium"}


def findings_needing_acceptance(ai: dict) -> set[str]:
    """Titles of the medium findings an approval over an uncertain review must name."""
    return {
        f["title"] for f in ai.get("findings", [])
        if isinstance(f, dict) and f.get("severity") == "medium" and isinstance(f.get("title"), str)
    }


def ai_review_acceptable_with(ai: dict, accepted: object) -> bool:
    """Whether a review that is not a certain pass may be published under a named
    approval accepting exactly its medium findings (Martin 2026-10-20, BN3)."""
    if ai.get("disposition") not in {"pass", "quarantine"}:
        return False
    findings = ai.get("findings")
    if not isinstance(findings, list) or any(
        not isinstance(f, dict) or f.get("severity") not in ACCEPTABLE_SEVERITIES for f in findings
    ):
        return False
    if not isinstance(accepted, list) or any(not isinstance(t, str) or not t for t in accepted):
        return False
    needed = findings_needing_acceptance(ai)
    return bool(needed) and set(accepted) == needed


def validate_submission(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("submission fields are invalid")
    version = value.get("schemaVersion")
    if version == 1:
        if set(value) != SUBMISSION_V1_FIELDS:
            raise ValueError("v1 submission fields are invalid")
        package_id = value.get("pluginId")
        kind = "plugin"
    elif version == 2:
        if set(value) != SUBMISSION_V2_FIELDS:
            raise ValueError("v2 submission fields are invalid")
        package_id = value.get("packageId")
        kind = value.get("kind")
        if kind not in {"plugin", "theme"}:
            raise ValueError("submission kind is invalid")
    else:
        raise ValueError("submission schemaVersion is unsupported")
    if not isinstance(package_id, str) or not ID.fullmatch(package_id):
        raise ValueError("submission package id is invalid")
    if not isinstance(value.get("version"), str) or not VERSION.fullmatch(value["version"]):
        raise ValueError("submission version is invalid")
    if not isinstance(value.get("repository"), str) or not REPOSITORY.fullmatch(value["repository"]):
        raise ValueError("submission repository is invalid")
    if not isinstance(value.get("commit"), str) or not COMMIT.fullmatch(value["commit"]):
        raise ValueError("submission commit is invalid")
    manifest = value.get("manifestPath")
    if (
        not isinstance(manifest, str)
        or manifest.startswith("/")
        or ".." in pathlib.PurePosixPath(manifest).parts
        or not manifest.endswith("manifest.json" if kind == "plugin" else "theme.json")
    ):
        raise ValueError("submission manifestPath is invalid")
    return value


def submission_kind(submission: dict) -> str:
    return "plugin" if submission["schemaVersion"] == 1 else submission["kind"]


def submission_id(submission: dict) -> str:
    return submission["pluginId"] if submission["schemaVersion"] == 1 else submission["packageId"]


def validate_manifest_identity(manifest: object, submission: dict) -> dict:
    if not isinstance(manifest, dict):
        raise ValueError("plugin manifest is not an object")
    if manifest.get("id") != submission_id(submission) or manifest.get("version") != submission["version"]:
        raise ValueError("manifest identity does not match the immutable submission")
    return manifest


def validate_publishable_audit(envelope: object, submission: dict) -> dict:
    """Validate every public audit field before it can enter a signed index."""
    if not isinstance(envelope, dict) or envelope.get("format") not in {
        "tine-plugin-audit-result/v1", "tine-package-audit-result/v1"
    }:
        raise ValueError("audit result format is invalid")
    if envelope.get("disposition") not in {"publish", "quarantine"}:
        raise ValueError("audit disposition is not publishable")
    if envelope.get("commitVerified") != submission["commit"]:
        raise ValueError("verified source commit does not match submission")

    checker = envelope.get("checker")
    if not isinstance(checker, dict) or checker.get("status") != "passed":
        raise ValueError("deterministic audit did not pass")
    if checker.get("risk") not in AUDIT_RISKS:
        raise ValueError("audit risk is invalid")
    if not isinstance(checker.get("checkedAt"), str) or not checker["checkedAt"]:
        raise ValueError("audit timestamp is invalid")

    ai = envelope.get("aiReview")
    if not isinstance(ai, dict):
        raise ValueError("AI source review is invalid")
    certain_pass = ai.get("disposition") == "pass" and ai.get("uncertain") is False
    approval = envelope.get("manualApproval")
    if not certain_pass and not (
        isinstance(approval, dict)
        and ai_review_acceptable_with(ai, approval.get("acceptedFindings"))
    ):
        raise ValueError("AI source review is not a certain pass")
    if not isinstance(ai.get("summary"), str) or not ai["summary"]:
        raise ValueError("AI source review summary is invalid")
    findings = ai.get("findings")
    if not isinstance(findings, list) or len(findings) > 50:
        raise ValueError("AI source review findings are invalid")
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or finding.get("severity") not in FINDING_SEVERITIES
            or not isinstance(finding.get("title"), str)
            or not finding["title"]
            or not isinstance(finding.get("impact"), str)
            or not finding["impact"]
        ):
            raise ValueError("AI source review finding is invalid")
    areas = ai.get("areasReviewed")
    if (
        not isinstance(areas, list)
        or len(areas) > 100
        or any(not isinstance(area, str) or not area for area in areas)
    ):
        raise ValueError("AI source review areas are invalid")

    if approval is not None and (
        not isinstance(approval, dict)
        or approval.get("by") not in MANUAL_APPROVERS
        or not isinstance(approval.get("note"), str)
        or not approval["note"]
        or not isinstance(approval.get("approvedAt"), str)
        or not approval["approvedAt"]
        or ("acceptedFindings" in approval and not ai_review_acceptable_with(ai, approval["acceptedFindings"]))
    ):
        raise ValueError("manual approval is invalid")
    if envelope["disposition"] == "quarantine" and approval is None:
        raise ValueError("quarantined audit requires explicit manual approval")
    return envelope


def validate_source_tree(root: pathlib.Path, max_bytes: int = 4 * 1024 * 1024, max_files: int = 5_000) -> None:
    """Reject links and oversized trees before any host-side source reads."""
    total = 0
    files = 0
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] == ".git":
            continue
        metadata = path.lstat()
        if path.is_symlink():
            raise ValueError(f"source symlinks are not accepted: {rel.as_posix()}")
        if not path.is_file():
            continue
        files += 1
        total += metadata.st_size
        if files > max_files or total > max_bytes:
            raise ValueError("plugin source tree exceeds the registry intake limit")
