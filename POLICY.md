# Registry policy

- Public source, immutable commit, recognized SPDX license, explicit capabilities,
  explicit supported platforms, and AI-development provenance are required.
- Published `id@version` bytes and SHA-256 are immutable.
- Plugin API 0.2 guests and theme API 0.1 packages may not require network
  telemetry or Tine telemetry.
- The deterministic import check must show exactly `env.memory`; the ABI exports are
  `tine_alloc`, `tine_handle`, and `tine_result_len`.
- A package-level `low` risk result means it has no graph-write capability and no
  deterministic or AI-review reason for quarantine. It is not a confidence score or
  a claim of zero bugs. Finding severities describe the possible impact of an
  individual observation: `info` is not a known harm, while `low` is a contained
  issue unlikely to affect notes.
- Deterministic pass + reproducible build + AI pass without uncertainty can
  auto-publish only when package risk is low.
- `graph.write.block`, source/binary mismatch, reviewer uncertainty, prompt-injection
  behavior, unusual build behavior, or any failed check quarantines automatically.
- Themes are inert literal colours and never execute. A theme whose deterministic
  check passes publishes automatically when the AI review does not reject it and
  reports no `medium`, `high` or `critical` finding, even if the reviewer marks
  itself uncertain (for example about README screenshot or palette-provenance
  claims it cannot verify). A theme with a `medium` finding needs a named approval
  that lists it; plugins keep the certain-pass rule above.
- Malicious versions are rejected; already-published unsafe versions are revoked in
  the signed index. Revocation records are immutable append-only entries.
- “Community” does not imply third-party authorship or core commitment. Martin may
  publish a community plugin without promising to adopt or maintain it in core.
