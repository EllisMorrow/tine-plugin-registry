#!/usr/bin/env python3
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import tomllib
from codex_review import review
from validation import (
    submission_kind, validate_manifest_identity, validate_source_tree, validate_submission,
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, **kwargs)


def safe_git(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    env = {
        "PATH": os.environ.get("PATH", ""), "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "LANG": "C.UTF-8",
    }
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *command], check=True, text=True, env=env, **kwargs)


def podman_base(
    image: str,
    source: pathlib.Path,
    plugin_root: pathlib.Path,
    cache: pathlib.Path,
    output: pathlib.Path,
    network: str,
) -> list[str]:
    workdir = pathlib.PurePosixPath("/src") / plugin_root.relative_to(source).as_posix()
    return [
        "podman", "--cgroup-manager=cgroupfs", "run", "--rm", f"--network={network}",
        "--cap-drop=all",
        "--security-opt=no-new-privileges", "--pids-limit=256", "--memory=1g", "--cpus=2",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "-v", f"{source}:/src:ro,Z", "-v", f"{cache}:/cache:rw,Z", "-v", f"{output}:/out:rw,Z",
        "--workdir", str(workdir),
        image,
    ]


def bwrap_base(
    source: pathlib.Path,
    plugin_root: pathlib.Path,
    cache: pathlib.Path,
    output: pathlib.Path,
    network: bool,
) -> list[str]:
    """Minimal credential-free root for hosts where rootless Podman is absent."""
    workdir = pathlib.PurePosixPath("/src") / plugin_root.relative_to(source).as_posix()
    command = [
        "bwrap", "--die-with-parent", "--new-session", "--unshare-user-try", "--cap-drop", "ALL",
        "--clearenv", "--setenv", "PATH", "/opt/cargo/bin:/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/tmp/home", "--setenv", "RUSTUP_HOME", "/opt/rustup",
        "--setenv", "LANG", "C.UTF-8",
        "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
        "--dir", "/opt", "--ro-bind", "/opt/cargo", "/opt/cargo",
        "--ro-bind", "/opt/rustup", "/opt/rustup",
        "--dir", "/etc", "--ro-bind", "/etc/ssl", "/etc/ssl",
        "--ro-bind", "/etc/alternatives", "/etc/alternatives",
        "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
        "--ro-bind", "/etc/hosts", "/etc/hosts",
        "--ro-bind", "/proc", "/proc", "--dev", "/dev",
        "--dir", "/home", "--dir", "/home/koutecky", "--tmpfs", "/tmp",
        "--ro-bind", str(source), "/src", "--bind", str(cache), "/cache",
        "--bind", str(output), "/out",
        "--ro-bind", str(pathlib.Path(__file__).with_name("container") / "build.sh"), "/builder.sh",
        "--chdir", str(workdir),
    ]
    if not network:
        command.append("--unshare-net")
    return [*command, "/bin/bash", "/builder.sh"]


def locked_sdk_source(plugin_root: pathlib.Path, temp: pathlib.Path, manifest: dict) -> list[tuple[str, pathlib.Path]]:
    lock_path = plugin_root / "Cargo.lock"
    if lock_path.is_symlink() or not lock_path.is_file():
        return []
    lock = tomllib.loads(lock_path.read_text())
    package = next((item for item in lock.get("package", []) if item.get("name") == "tine-plugin-sdk"), None)
    source = package.get("source", "") if package else ""
    prefix = "git+https://github.com/martinkoutecky/tine?"
    if not source.startswith(prefix) or "#" not in source:
        return []
    commit = source.rsplit("#", 1)[1]
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        return []
    checkout = temp / "sdk-source"
    safe_git(["clone", "--filter=blob:none", "--no-checkout", "https://github.com/martinkoutecky/tine", str(checkout)])
    safe_git(["-C", str(checkout), "fetch", "--depth=1", "origin", commit])
    safe_git(["-C", str(checkout), "checkout", "--detach", commit])
    sdk = checkout / "plugin-sdk" / "rust"
    sources = [(f"locked-tine-plugin-sdk@{commit}", sdk)] if sdk.is_dir() else []
    if manifest.get("contributions", {}).get("blockDecorations"):
        evidence = temp / "host-decoration-evidence"
        for relative in [
            "src/plugins/manager.ts", "src/plugins/manifest.ts",
            "src/components/Block.tsx", "src/styles/app.css",
            # Setting-to-style boundary (plugin API 0.3): validation and row styling.
            "src/components/block/rowChrome.tsx", "src/plugins/settings.ts",
            "src/plugins/color.mjs",
        ]:
            source = checkout / relative
            if not source.is_file():
                continue  # older locked revisions predate some of these files
            destination = evidence / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        sources.append((f"locked-tine-host-decoration@{commit}", evidence))
    return sources


def port_evidence_path_relevant(path: pathlib.Path, kind: str) -> bool:
    """Keep theme evidence focused on authored styling, not whole application bundles."""
    name = path.name.lower()
    metadata = name in {"license", "copying", "notice", "manifest.json", "package.json"} or name.startswith("readme")
    if metadata:
        return True
    if kind == "theme":
        if ".bundle." in name or ".min." in name:
            return False
        return path.suffix.lower() in {".css", ".scss", ".sass", ".less"}
    return path.suffix.lower() in {".css", ".scss", ".js", ".ts", ".tsx"}


def pinned_port_source(manifest: dict, temp: pathlib.Path, kind: str) -> list[tuple[str, pathlib.Path]]:
    """Fetch declared port evidence as inert review input; never build or execute it."""
    port = manifest.get("portedFrom")
    if not isinstance(port, dict):
        return []
    source, revision = port.get("source"), port.get("revision")
    if (
        not isinstance(source, str)
        or not source.startswith("https://github.com/")
        or not isinstance(revision, str)
        or len(revision) != 40
        or any(char not in "0123456789abcdef" for char in revision)
    ):
        return []
    checkout = temp / "ported-source"
    safe_git(["clone", "--filter=blob:none", "--no-checkout", source, str(checkout)])
    safe_git(["-C", str(checkout), "fetch", "--depth=1", "origin", revision])
    safe_git(["-C", str(checkout), "checkout", "--detach", revision])
    actual = safe_git(["-C", str(checkout), "rev-parse", "HEAD"], capture_output=True).stdout.strip()
    if actual != revision:
        raise RuntimeError("ported source did not resolve to the declared revision")
    evidence = temp / "ported-evidence"
    evidence.mkdir()
    copied_bytes = 0
    for path in sorted(checkout.rglob("*")):
        if path.is_symlink() or not path.is_file() or ".git" in path.relative_to(checkout).parts:
            continue
        if not port_evidence_path_relevant(path, kind):
            continue
        size = path.stat().st_size
        if copied_bytes + size > 400_000:
            raise RuntimeError("declared port evidence exceeds the review limit")
        destination = evidence / path.relative_to(checkout)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        copied_bytes += size
    return [(f"declared-ported-source@{revision}", evidence)]


def audit(submission_path: pathlib.Path, tine: pathlib.Path, image: str, max_source: int) -> dict:
    submission = validate_submission(json.loads(submission_path.read_text()))
    with tempfile.TemporaryDirectory(prefix="tine-plugin-audit-") as temp:
        temp_path = pathlib.Path(temp)
        source, cache, output = temp_path / "source", temp_path / "cache", temp_path / "output"
        cache.mkdir(); output.mkdir()
        safe_git(["clone", "--filter=blob:none", "--no-checkout", submission["repository"], str(source)], timeout=300)
        safe_git(["-C", str(source), "fetch", "--depth=1", "origin", submission["commit"]], timeout=300)
        safe_git(["-C", str(source), "checkout", "--detach", submission["commit"]], timeout=300)
        actual = safe_git(["-C", str(source), "rev-parse", "HEAD"], capture_output=True).stdout.strip()
        if actual != submission["commit"]:
            raise RuntimeError("checkout did not resolve to the submitted commit")
        validate_source_tree(source)
        manifest_path = (source / submission["manifestPath"]).resolve()
        if source.resolve() not in manifest_path.parents:
            raise RuntimeError("manifest path escaped checkout")
        if not manifest_path.is_file():
            raise RuntimeError("manifest path is not a regular file")
        plugin_root = manifest_path.parent
        manifest = validate_manifest_identity(json.loads(manifest_path.read_text()), submission)
        kind = submission_kind(submission)
        if kind == "theme":
            completed = subprocess.run(
                ["node", str(tine / "scripts/tine-theme.mjs"), "check", str(plugin_root), "--json"],
                capture_output=True, text=True, check=False,
            )
            if not completed.stdout.strip():
                raise RuntimeError(f"theme checker produced no report: {completed.stderr[:500]}")
            checker = json.loads(completed.stdout)
            checker["risk"] = "low"
            checker["provenance"] = {
                "sourceCommit": actual,
                "manifestLoadedFromThatCheckout": True,
                "dependencyFetchHadNoCredentials": True,
                "buildNetwork": "not-applicable",
                "manifestSha256": checker.get("sha256"),
            }
            port_sources = pinned_port_source(manifest, temp_path, "theme")
            ai = review(
                plugin_root, checker,
                pathlib.Path(__file__).parents[1] / "schemas" / "audit.schema.json",
                max_source, extra_sources=port_sources, kind="theme",
            )
            deterministic_pass = checker.get("status") == "passed"
            if not deterministic_pass:
                disposition = "quarantine"
            elif ai["disposition"] == "reject":
                disposition = "reject"
            elif ai["disposition"] == "pass" and not ai["uncertain"]:
                disposition = "publish"
            else:
                disposition = "quarantine"
            return {
                "format": "tine-package-audit-result/v1",
                "submission": submission,
                "commitVerified": actual,
                "checker": checker,
                "aiReview": ai,
                "disposition": disposition,
                "package": {
                    "manifest": manifest,
                    "manifestSha256": hashlib.sha256(canonical(manifest)).hexdigest(),
                },
            }
        entry_rel = manifest.get("entry")
        if not isinstance(entry_rel, str):
            raise RuntimeError("plugin manifest entry is invalid")
        entry = (plugin_root / entry_rel).resolve()
        if plugin_root.resolve() not in entry.parents:
            raise RuntimeError("plugin entry escaped its source root")
        use_podman = shutil.which("podman") is not None
        if not use_podman and shutil.which("bwrap") is None:
            raise RuntimeError("neither rootless Podman nor Bubblewrap is available")
        fetch = (podman_base(image, source, plugin_root, cache, output, "slirp4netns")
                 if use_podman else bwrap_base(source, plugin_root, cache, output, True))
        run([*fetch, "fetch"], timeout=600)
        build = (podman_base(image, source, plugin_root, cache, output, "none")
                 if use_podman else bwrap_base(source, plugin_root, cache, output, False))
        run([*build, "build"], timeout=600)
        expected = pathlib.Path(manifest["entry"]).name
        artifact = output / "artifacts" / expected
        if not artifact.is_file():
            raise RuntimeError(f"build did not produce declared entry {expected}")
        entry.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact, entry)
        checker_path = temp_path / "check.json"
        completed = subprocess.run(
            ["node", str(tine / "scripts/tine-plugin.mjs"), "check", str(plugin_root), "--json"],
            capture_output=True, text=True, check=False,
        )
        if not completed.stdout.strip():
            raise RuntimeError(f"plugin checker produced no report: {completed.stderr[:500]}")
        checker_path.write_text(completed.stdout)
        checker = json.loads(completed.stdout)
        checker["provenance"] = {
            "sourceCommit": actual,
            "artifactBuiltFromThatCheckout": True,
            "dependencyFetchHadNoCredentials": True,
            "buildNetwork": "none",
            "artifactSha256": checker.get("wasm", {}).get("sha256"),
        }
        extra_sources = [
            *locked_sdk_source(plugin_root, temp_path, manifest),
            *pinned_port_source(manifest, temp_path, "plugin"),
        ]
        ai = review(
            plugin_root,
            checker,
            pathlib.Path(__file__).parents[1] / "schemas" / "audit.schema.json",
            max_source,
            extra_sources,
            kind="plugin",
        )
        deterministic_pass = checker.get("status") == "passed"
        low_risk = checker.get("risk") == "low"
        if not deterministic_pass:
            disposition = "quarantine"
        elif ai["disposition"] == "reject":
            disposition = "reject"
        elif low_risk and ai["disposition"] == "pass" and not ai["uncertain"]:
            disposition = "publish"
        else:
            disposition = "quarantine"
        return {
            "format": "tine-plugin-audit-result/v1",
            "submission": submission,
            "commitVerified": actual,
            "checker": checker,
            "aiReview": ai,
            "disposition": disposition,
            "package": {
                "manifest": manifest,
                "manifestSha256": hashlib.sha256(canonical(manifest)).hexdigest(),
                "wasmBase64": base64.b64encode(artifact.read_bytes()).decode("ascii"),
                "sha256": checker["wasm"]["sha256"],
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("submission", type=pathlib.Path)
    parser.add_argument("--tine", type=pathlib.Path, required=True)
    parser.add_argument("--image", default="localhost/tine-plugin-builder:0.1")
    parser.add_argument("--max-source-bytes", type=int, default=524288)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = audit(args.submission, args.tine, args.image, args.max_source_bytes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp = args.output.with_suffix(".tmp")
    temp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    os.replace(temp, args.output)


if __name__ == "__main__":
    main()
