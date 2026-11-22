# Changelog

All notable changes to GeDefense Windows are documented here. The project follows a
versioned release history; `VERSION` is the authoritative version for builds.

## [6.1.0] - 2026-11-22

### Added — Microsoft Defender Deep Symbiosis, Reversible Containment & Agent Onboarding

- **Microsoft Defender Deep Symbiosis (`internal/mhx/defender_*`, `internal/mhx/fair_scorer.go`):** Continuous correlation across 16 Defender operational event IDs (malware detections `1116`–`1117`, remediation failures `1118`–`1119`, ASR `1121`–`1122`, CFA `1123`–`1124`, Network Protection `1125`–`1126`, restore `5004`, tamper/weakening events `5000`–`5001`, `5007`, `5010`–`5013`) with bounded field payloads, 60s-cooldown automatic Defender self-heal reconciliation (`5001`/`5007`/`5010`/`5012`), bilateral `FairScorer` trust modulation (`CalculateFairScoreWithSymbiosis`), Defender artifact scan/oracle verification (`POST /api/v1/mhx/defender/scan-file`), and bidirectional posture reconciliation (`POST /api/v1/mhx/defender/reconcile`).
- **Reversible `NtSuspendProcess`-Tree Containment (`internal/winapi/process_suspend_windows.go`, `internal/mhx/containment*`):** Pinned PID+CreationTime+image suspension/resume of active threat process trees with bounded containment tracking, automatic containment-safe inspection (`GET /api/v1/mhx/containments`), explicit operator resume (`POST /api/v1/mhx/containments/{id}/resume` requiring `"RESUME CONTAINED PROCESS"`), and explicit termination (`POST /api/v1/mhx/containments/{id}/terminate`).
- **Titan → Defender Artifact Oracle (`internal/titan/engine.go`):** Bounded background artifact inspection bridging high-risk Titan ingress/persistence detections into Defender intelligence (`SetArtifactOracle`, `oracleSem`).
- **Glass 2100 XDR Symbiosis & Containment Surface (`internal/server/web/*`):** Live Defender Symbiosis telemetry, containment controls, and one-click verification/reconcile in the MHX XDR dashboard across DE/EN/RU/ZH.
- **First-Run Setup Wizard & Offline `AGENTS.md` Blueprint (`internal/server/web/agents-blueprint.js`, `setup-wizard.js`, `index.html`):** Guided host-, software-, and toolchain-tailored `AGENTS.md` export, clipboard copy, and starter prompt in the Setup Wizard and System view — 100% local with zero inbound/remote AI APIs or exposed credentials.

### Fixed

- **Inno Setup 7 UTF-8 BOM & Localization Hygiene (`installer/inno/`):** Added UTF-8 BOM (`EF BB BF`) to `GeDefense.iss` and all `terms/*.txt` files so localized umlauts, em-dashes, Cyrillic, and Simplified Chinese render without Windows-1252 mojibake, and updated license headers/messages to `6.1.0`.
- **Threat-Intel Prefix Parser Resilience (`internal/threatintel/validate.go`, `parser.go`):** Skip over-broad `< /16` or `< /32` feed prefixes gracefully inside `parseNDJSON` instead of aborting the entire Spamhaus feed.
- **AppControl & AppList Self-Healing (`xdr/Set-VgtMhxApp*.ps1`):** Automatic NUL/corrupt JSON quarantine and clean state recovery without breaking idempotent rule updates.
- **Per-Path Long-Operation Rate Budgets (`internal/server/middleware.go`):** Isolated `rateLong` request budgets per normalized endpoint path so threat-intel/reconcile calls do not starve setup/hardening transitions.

## [6.0.0] - 2026-11-16

### Added — V6 Sovereign Anti-Spyware & Kernel Telemetry

- **Anti-Spyware Sensors (`internal/spyware` + `internal/app/v6_sensors.go`, `v6_windows.go`):** BYOVD vulnerable-driver & Authenticode verification (`WinVerifyTrust`), webcam/microphone/screen-capture/location capability consent store monitoring, Windows persistence detection (`IFEO`, `SilentProcessExit`, `AppCertDlls`, `AppInit_DLLs`, LSA security/notification packages, Print Monitors), and LSASS Event Log (`4656`/`4663`) `PROCESS_VM_READ` inspection.
- **Out-of-Band Evidence Witness (`internal/witness`):** Signed Ed25519 ledger checkpoints with AES-256-GCM outbox, SPKI-pinned HTTPS transport, fail-closed rollback/fork detection, and air-gapped `vgtw1:` export support.
- **StyX Passive Egress & Beaconing Detector (`internal/mhx/styx_*` + `internal/winapi/tcp_estats_windows.go`):** IPv4/IPv6 TCP flow telemetry, receive-byte estats correlation, and periodic beacon scoring in `OBSERVE_ONLY` mode.
- **Emergency Lockdown Engine (`internal/lockdown`):** Crash-safe AES-256-GCM state with `expected_epoch` Compare-Set release, Composite BadUSB device classifier, and PID+CreationTime-bound broker process freezer.
- **Ephemeral Parser Cells (`internal/parsercells`):** Zero-capability Windows AppContainer isolation, Job Object resource limits, `Win32kSystemCallDisable` + 5 process mitigations, and handle-only I/O.
- **Native WinAPI V6 Foundations (`internal/winapi`):** Real-time ETW consumer (`StartTraceW`/`ProcessTrace`/`tdh.dll`), direct WFP filter transactions (`fwpuclnt.dll`) + `SetTcpEntry`, and TPM 2.0 / TCG WBCL / Secure Boot / HVCI measured boot posture (`tbs.dll` + `ncrypt.dll`).
- **Control Plane & Web UI:** `GET /api/v1/v6/status`, `/api/v1/v6/spyware/findings`, `/api/v1/v6/styx/incidents`, and the **V6 Sovereign** dashboard view.

### Security & Supply-Chain Hardening

- **VGT-100 Security Remediation (`FIND-WIN-001`..`FIND-WIN-023`):** Fail-closed de-elevation for Center & Tray, operator broker Authenticode & kernel image binding, signed Titan persistence/quarantine evidence with `RESTORED_DEGRADED` recovery, HMAC-protected evidence high-water & threat-intel clock anchors, fail-closed `secretfs` pre-write DACLs, and release-channel hygiene with prerelease-aware installer downgrade protection.
- **Toolchain CVE Fix (`GO-2026-6859`):** Pinned Go release toolchain updated from `1.26.10` to `1.26.11` (`net/http` header race fix).

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
