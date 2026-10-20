# Tine community plugin registry

Public catalogue, immutable version metadata, audit reports, quarantine decisions,
and signed revocations for [Tine](https://github.com/martinkoutecky/tine)'s
capability-limited WebAssembly plugins and inert semantic-color themes.

Human-written, AI-assisted, and AI-primary plugins are equally welcome. AI provenance
is disclosed but is not a security score. Ordinary plugins have no ambient network,
filesystem, process, DOM, browser, Tauri, or graph-path access.

## Submit a version

1. Publish source under a recognized open-source license. Plugins commit `Cargo.lock`.
2. From a clean checkout, run Tine's `plugin:check` or `theme:check` command.
3. Add one immutable `submissions/<package-id>/<version>.json` file in a pull request.
4. GitHub performs metadata-only intake. It does not execute pull-request code.
5. Martin's local auditor checks out the exact commit, builds it in a fresh rootless
   Podman sandbox (or the audited Bubblewrap fallback) with no secrets when executable code must be built, runs the
   package-specific deterministic checker, and asks a no-tools Codex process for a
   structured source and provenance review.
6. Passing low-risk versions may publish automatically. Anything uncertain or with
graph-write authority quarantines for explicit review. Theme packages never execute:
they are accepted only as a bounded allowlist of literal semantic colors.

Every public version links its deterministic and AI reports. Passing is evidence, not
a guarantee. The signed index pins separate SHA-256 digests for each manifest and
WASM artifact as well as the complete public safety report. It also records whether
publication was automatic or a named manual approval. A manual approval over an AI
review that is not a certain pass must name each medium finding it accepts, and those
names are in the public report; a high or critical finding or a rejecting review can
never be approved. Tine checks these bytes before
displaying the report. See [POLICY.md](POLICY.md), [SECURITY.md](SECURITY.md), and
[`auditor/README.md`](auditor/README.md).
