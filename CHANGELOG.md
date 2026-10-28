# Changelog

All notable changes to GeDefense Windows are documented here. The project follows a
versioned release history; `VERSION` is the authoritative version for builds.

## [5.3.0] - 2026-10-28

### Added

- **Sentinel / Killerdom console:** granular signature toggles, curated Windows
  system-app isolation, allowlist management with optional SHA-256 and
  signer/publisher pins, Ghost Mode controls and Titan/Killerdom correlation.
- **Execution provenance:** system apps and allowlist entries are checked by
  canonical path, PE `OriginalFilename`, Authenticode status and publisher, not
  by image name alone. System/self-protection entries are immutable.
- **Titan → Killerdom bridge:** Titan integrity breaches can terminate verified
  malicious persistence; success and failure are written to the HMAC-chained
  evidence ledger.
- **Ghost Mode enforcement:** outbound telemetry programs/services are blocked
  through WFP-backed Windows Firewall rules and Microsoft telemetry hosts are
  sinkholed. State is reconciled at boot and exposed as `applied`/`lastError`.
- **AMSI scan-buffer integrity monitoring** for living-off-the-land processes,
  with bounded remote module identity checks and error throttling.
- **Installer anti-rollback guard:** an older installer cannot replace a newer
  installation; equal-version repair remains allowed.
- **API v5 aliases** under `/api/v5/sentinel/*`, sharing the same handlers and
  authorization gates as v1.
- **Full localization of the Sentinel page** for English, Russian and Simplified
  Chinese, including signature/system-app descriptions and dynamic UI messages.
- **Incident-response runbook** (`docs/SECURITY-INCIDENT-RESPONSE.md`).

### Changed

- Sentinel sections use explicit vertical spacing (30 px rhythm) and the Glass
  2100 material language; inline styles are avoided.
- Allowlist and system-app writes require a reason and, where protection is
  reduced, the typed confirmation phrase.
- Titan policy mutations require the `CHANGE TITAN POLICY` confirmation.

### Fixed

- Empty or partially rendered Sentinel tables caused by a missing signature
  pattern contract and unguarded row rendering.
- False positives that terminated benign commands:
  - every `cmd.exe /c …` invocation (KD-SIG-04),
  - 64-character hash literals (KD-SIG-02),
  - `-ExecutionPolicy Bypass`/`hidden`/`Invoke-` alone (KD-SIG-01),
  - `go list -e` / `node -e` misread as PowerShell encoded commands.
- Ghost Mode reported success while performing no OS-level action; firewall
  rules failed on localized Windows (`netsh` output) and used relative binaries.
- AMSI identity lookup failed on the local `amsi.dll`; module size and bounds are
  now validated and scan failures no longer flood the ledger.
- Hosts staging files created Titan HIGH events inside System32; staging now
  happens under `%ProgramData%\VGT\GeDefense`.
- Installer/version drift: stale documentation and release metadata.

### Security

- VGT-100 review: 81/81 applicable controls PASS, 0 FAIL, no open
  CRITICAL/HIGH findings; release gate `ELIGIBLE_FOR_REVIEW`.
- Verified controls include scoped sessions, replay IDs, rate limits, CSP and
  security headers, strict bounded JSON, ZIP traversal protection, HMAC-chained
  evidence, AES-256-GCM quarantine, signed installer and zero third-party Go
  dependencies.
- `govulncheck ./...`: no vulnerabilities found.
- Installer Authenticode signature valid; a tampered copy is detected as
  `HashMismatch`.

### Known limitations

- Public beta; the installer is self-signed (no public CA, RFC 3161 timestamp,
  CRL/OCSP or externally anchored anti-rollback channel yet).
- Kernel/firmware compromise, a malicious local administrator and complete
  supply-chain compromise remain outside the product boundary.
- WFP rules cover telemetry programs/services, not arbitrary port/IP callouts.
- No full external DAST scanner, long-duration soak or independent third-party
  audit was performed for this release.

## [5.2.0]

- Four UI languages (German, English, Russian, Simplified Chinese) and a clean
  source release.
- README consolidation, attribution for jsVectorMap and GeoIP/ASN data.
- Installer/upgrade reliability, legacy baseline migration and corrected
  self-relative DACL verification.
- TITAN 5.2 identity and window title.

## [5.1.4]

- Scoped operator sessions through a loopback broker; break-glass master token
  restricted to SYSTEM/Administrators.
- Installer downgrade protection, evidence-witness improvements and
  distribution-hygiene gate.
- Deterministic SBOM/provenance/sidecar chain and publish gate.

## [5.1.3]

- Go 1.26.10, `govulncheck` release gate and CycloneDX SBOM.
- API authentication scopes, replay IDs, rate limits, security headers and typed
  confirmations.
- Titan/data-plane hardening: inheritance-protected secret directories, feed
  authority, HMAC-authenticated overrides, bounded ADS reads and vault quota.

## [5.1.2]

- Titan visual refresh and faster startup readiness.
- BITS/maintenance-service tolerance, finding coalescing and stable watcher
  heartbeat.

## [5.1.1]

- Titan field fixes and UI consistency corrections.

## [5.1.0]

- GeDefense Titan: owner policy, evidence journal, quarantine vault and native
  Windows sensors.

## [5.0.0]

- Configurable security fabric and unified Windows security-center surface.
