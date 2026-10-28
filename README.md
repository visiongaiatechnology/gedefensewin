<div align="center">

<img width="256" height="256" alt="GeDefense Windows" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />

# VGT GeDefense Titan

### Sovereign Endpoint Security Center &amp; Kinetic Threat Fabric

**English** · [Deutsch](README.de.md) · [Русский](README.ru.md) · [中文](README.zh.md)

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-5.3.0-orange?style=for-the-badge)](#release-history-v5)
[![Status](https://img.shields.io/badge/Status-Public_Beta-yellow?style=for-the-badge)](#public-beta-advisory)
[![Platform](https://img.shields.io/badge/Platform-Windows_11_x64-lightgrey?style=for-the-badge&logo=windows)](#system-requirements)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#local-sovereignty-and-privacy)
[![Architecture](https://img.shields.io/badge/Architecture-Zero_Go_Dependencies-blue?style=for-the-badge)](#architecture)
[![Evidence](https://img.shields.io/badge/Evidence-HMAC--SHA256_Ledger-gold?style=for-the-badge)](#what-is-geodefense-titan)
[![Signing](https://img.shields.io/badge/Signing-Self--Signed_Beta_Only-lightgrey?style=for-the-badge)](#verification-and-trust)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**DEFENDER · WFP FIREWALL · ASR · APP CONTROL · KINETIC DEFENSE · MHX EDR/XDR · TITAN INTEGRITY · NATIVE TRAFFIC · GEOIP/ASN**

<br />

[Installation and releases](https://github.com/visiongaiatechnology/gedefensewin/releases) · [Architecture](ARCHITECTURE.md) · [Titan concept](docs/TITAN.md) · [Build guide](docs/BUILDING.md) · [Operations](docs/OPERATIONS.md) · [Security policy](SECURITY.md)

</div>

---

<img width="1536" height="1024" alt="GeDefense_ Real Security, Many Feathers" src="https://github.com/user-attachments/assets/68406427-a185-4fa5-b06a-af874a747dcb" />



> [!IMPORTANT]
> **Installer update (5.3.0):** The previous self-signed PowerShell bootstrap could fail on fresh Windows installations because the VGT certificate was not trusted. The release now uses a branded **Inno Setup installer** that imports the beta certificate automatically after you accept the licence — no manual certificate import is required.
>
> **[Download the GeDefense Windows 5.3.0 installer](https://github.com/visiongaiatechnology/gedefensewin/releases/download/v5.3.0/GeDefense-Setup-x64-v5.3.0.exe)**

## ⚠️ Public Beta Advisory

> [!IMPORTANT]
> **Status: Public Beta — GeDefense Windows 5.3.0.**
>
> GeDefense Titan is under active development. **This beta can contain errors — including security defects.** We work continuously on hardening, testing and fixes, and we welcome every reproducible report.
>
> - Please use the beta on test systems first, keep backups and do not rely on it as the only security control of a productive environment.
> - Report bugs, security issues and feature requests via [GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues) or responsibly via [SECURITY.md](SECURITY.md).
> - This release is **self-signed** and has **no public CA trust**; there is no RFC 3161 timestamp, CRL/OCSP revocation path or externally anchored anti-rollback channel yet. For these reasons, 5.3.0 is **not a publicly trusted release**. See [Verification and trust](#verification-and-trust).
> - The core architecture is verified by automated release gates (Go race, Go vet, govulncheck, SBOM, provenance, installer and publish gates). Live installation and security-policy mutations still belong on an isolated test VM.

---

## What is GeDefense Titan?

GeDefense Titan is a local, sovereign security console for Windows 11. It unifies the Windows security layers into one operator surface and adds its own authorization, evidence and integrity layer:

- **Windows control fabric:** Defender, ASR, Windows Firewall/WFP, App Control, audit policy, SMB/RDP/LSA/UAC settings and hardening components are measured, compared against a baseline, and can be applied idempotently with evidence.
- **MHX EDR/XDR:** native process, Defender and network correlation, process ancestry, owning-PID resolution, encoded-command detection and guarded response actions.
- **Threat Intelligence:** curated feeds, validated per-feed authority, WFP block generation and strict lifecycle limits.
- **Kinetic Defense:** burst correlation for real inbound WFP block events (OBSERVE_ONLY by default; ARMED requires explicit operator confirmation and verified active telemetry).
- **Native network telemetry and local GeoIP/ASN map:** RX/TX interface counters and local CSV-based country/ASN attribution for actually observed sources — no external IP lookup, no invented host positions.
- **Titan:** the integrity, authorization and evidence layer described below.
- **Local-only control plane:** the service listens on loopback (`127.0.0.1:17831`). There is no cloud control plane and no silent telemetry to third parties.

### Titan — Sovereign Endpoint Integrity

Titan answers a question that classic antivirus tools often blur: *was this change authorized by the owner?* Every change is classified as `AUTHORIZED`, `TOLERATED`, `UNEXPECTED` or `COMPROMISED`, based on the stored owner policy — not on the fact that a process is signed or that an administrator started it.

Titan combines:

- a native Windows sensor (`ReadDirectoryChangesW` with overlapped I/O) for protected system, startup, driver, task and user-ingress paths;
- SHA-256 evidence, zone identifiers, native process lists, TCP context and temporal process/network correlation — without invented file-to-PID attribution;
- a persistence and security inventory (services, Run/RunOnce keys, Defender/firewall/LSA/UAC/SMB/RDP/PowerShell logging controls, secure-boot state) with baselines that are only advanced after evidence has been written successfully;
- an append-only, HMAC/SHA-256-chained evidence journal with Ed25519-signed checkpoints, integrity verification and signed retention archives;
- an AES-256-GCM quarantine vault with bounded file size, SHA-256 verification, original-path traceability and controlled restore that never overwrites an existing target;
- owner policy (`OBSERVE`, `CONTAIN`, `STRICT`), owner permits, development-tree markers, review decisions and native Windows block toasts.

**Honest limits:** no claim of complete attribution, no protection against full kernel/firmware compromise, no TPM measured-boot attestation and no minifilter-based execution blocking in this phase. These limits are documented in the UI and in [`docs/TITAN.md`](docs/TITAN.md).

---

## What's new in 5.3.0

- **Sentinel / Killerdom execution plane:** real-time signature and behavioral response, strict parent-child lineage, canonical System32 path checks, AMSI scan-buffer integrity monitoring and a default-deny Paranoia gate.
- **Execution provenance instead of a free pass:** curated system apps and allowlist entries are verified by path, PE OriginalFilename, Authenticode signer/publisher and an optional SHA-256 pin; the allowlist never suppresses a high-confidence kill.
- **Titan to Killerdom bridge:** Titan integrity breaches can neutralize malicious persistence through verified PID termination; every action and failure is recorded in the HMAC-chained evidence ledger.
- **Ghost Mode that actually enforces:** outbound telemetry programs and services are blocked through WFP-backed Windows Firewall rules, Microsoft telemetry hosts are sinkholed, and the state is reconciled at boot and reported truthfully (`applied` / `lastError`).
- **False-positive hardening:** signatures for PowerShell obfuscation, base64 blobs and destructive `cmd /c` patterns were narrowed; the encoded-command parser now applies only to PowerShell hosts. Benign admin/test commands and `govulncheck` are no longer killed.
- **Hardening and supply chain:** scoped sessions, typed confirmation plus reason for posture reductions, SHA-256/signer-pinned allowlist entries, immutable self-protection, v5 API aliases, signed installer, SBOM/provenance, zero third-party Go dependencies and `govulncheck` 0.
- **UI and localization:** Sentinel/Killerdom tables render independently with empty states; all four UI languages (German, English, Russian, Simplified Chinese) cover the new page; spacing and the Glass 2100 layout were corrected.

## Built for critical scenarios

GeDefense Windows 5.3.0 is designed for Windows 11 endpoints where the operator must keep control in isolated, regulated or offline environments: local-only control plane, no cloud dependency, verifiable evidence, bounded resources and explicit response boundaries. It is **not** a claim of complete protection: kernel/firmware compromise, a malicious local administrator and a full supply-chain compromise remain outside the product boundary; the build is self-signed and still a public beta.

## Release history V5

### 5.3.0 — Sentinel execution plane, provenance hardening and critical-scenario readiness

- Sentinel/Killerdom console with signature toggles, system-app isolation, allowlist pinning, enforced Ghost Mode and Titan correlation.
- VGT-100 security review: 81/81 applicable controls PASS, 0 FAIL, no open CRITICAL/HIGH findings; release gate `ELIGIBLE_FOR_REVIEW`.
- Live-verified: Ghost Mode 9 firewall rules plus hosts sinkhole and rollback; Sentinel rendering 6/9/14 rows; `govulncheck` 0; signed installer.
- Documented limits: public beta, self-signed, local admin/SYSTEM compromise outside the product boundary.

**Full changelog:** [CHANGELOG.md](CHANGELOG.md)

### 5.2.0 — Internationalization and clean source release

- **Four UI languages:** German, English, Russian and Simplified Chinese, with a language switcher in the header and automatic detection from the system/browser language.
- **Clean repository:** generated build output (`work/`, `payload/`, `release/`, `sbom/`), handoff/agent artifacts and historical verification reports are no longer part of the source tree; `.gitignore` and the release gate enforce the separation.
- **README consolidation:** release history, Titan explanation, security-fix summary, licensing and third-party attribution now live in one maintained document in four languages.
- **Attribution:** jsVectorMap map geometry (MIT, `world-merc.js` 1.7.0) and the ASN database source **iplocate/ip-address-databases** (CC BY-SA 4.0) are explicitly credited (see [Licenses and attribution](#licenses-and-attribution)).
- **Version identity:** `VERSION`/Go product version 5.2.0; deterministic SBOM, provenance and signed installer are produced by the build pipeline.
- **Installer and upgrade reliability:** the installer falls back to a safe temporary staging directory when the per-user cache is unavailable; publisher trust is imported through the certificate store instead of an interactive `Import-Certificate` prompt; legacy hardening/MHX baselines are archived and migrated instead of blocking upgrades; audit-policy backups and signed-script handling survive reinstalls; the service starts with correct self-relative DACL verification.
- **UI identity:** the TITAN 5.2 badge and the `GeDefense V5 · Windows Security Center` window title identify the current release.

### 5.1.4 — Audit remediation 2 (remaining locally fixable findings)

- **Operator authentication:** Center and Tray no longer read the long-lived `dashboard.token`. A new loopback operator broker verifies the caller's Windows process token (membership in `VGT GeDefense Operators` or Administrators), issues short-lived scoped sessions and audits the OS account. The data root and master token are SYSTEM/Administrators-only.
- **Downgrade protection:** the installer refuses to overwrite a newer installation (`-AllowDowngrade` only for an explicit, documented rollback).
- **Evidence and handoff:** remaining live journals removed from the delivery package (archived with SHA-256); optional external evidence witness with truncation detection; the distribution-hygiene gate hard-fails on journals, keys, tokens and `.git` metadata.
- **Host hardening:** foreign/pre-created single-instance objects are no longer accepted as authority; browser executables are Authenticode-verified before launch.
- **Supply chain:** deterministic SBOM/provenance/sidecar chain with cross-verification, fail-closed publish gate, and a CI workflow definition.
- **Accepted external blockers:** public CA signing identity, RFC 3161 timestamp, CRL/OCSP, an externally anchored anti-rollback channel and feed signing keys remain open by owner decision; they are **not** counted as pass.

### 5.1.3 — Security-audit remediation and supply chain

- Go 1.26.10; `govulncheck -mode=binary` as a mandatory release gate (0 reachable vulnerabilities on all four binaries).
- Real CycloneDX SBOM, deterministic reproducible source archive, provenance artifact, package hygiene checks and fail-closed publish verification.
- API/authentication: server-side scopes (read/operate/policy/window), scoped sessions, revoke/logout, rotation, absolute/idle expiry, per-class rate limits, mandatory replay IDs, security headers on early rejections, opaque engine errors, typed confirmation plus reason for security-reducing changes. Browser bootstrap no longer carries a secret in Chromium arguments.
- Titan/data plane: inheritance-protected secret directories, signed feed-authority verifier, hard feed TTL with explicit `UNCONFIGURED` state, HMAC-authenticated overrides, reparse-safe paths, bounded ADS reads, vault quota/retention, rotating evidence archives, append-error surfacing and clock-rollback handling.
- Host/MHX: full encoded-command prefix normalization, watcher rejection of UNC/device/reparse image paths, local-only XDR signature checks, PID-reuse-safe process-tree termination, identity-scoped single-instance objects and MHX baseline/integrity binding.
- Result: 33 of 48 deep-audit findings fixed, 10 partially mitigated, 5 external trust blockers documented (continued in 5.1.4).

### 5.1.2 — Legibility, Titan visual refresh and fast readiness

- White typography across the security center and Titan; hierarchy through size, weight, spacing and surfaces; semantic states stay visible via tinted surfaces, borders and status dots.
- Titan adopts the Glass 2100 material language: compact control stage, ice-blue primary signals, bronze only as evidence accent, segmented tabs and dense sensor rows.
- Faster startup gate via cached health status, 3 s policy reconcile bound, background feed sync, no blocking network sync.
- BITS/maintenance-service start-type changes are `TOLERATED` when image path, service type and account stay unchanged; identical open findings are coalesced into one toast within ten minutes; bulk review of up to 100 findings; stable watcher heartbeat and reduced temp-deletion noise.

### 5.1.1 — Titan field fixes

- Noise filter for PowerShell policy test files, driver dumps and non-executable temp artifacts; tolerated classification for non-executable medium-score ingress files.
- Service normalization for `C:\Windows` vs `%SystemRoot%` and case drift.
- Owner permits (path, optional SHA-256, action, expiry, one-time) and development-tree markers, each with an evidence event.
- More Titan/server tests and an expanded browser fixture.

### 5.1.0 — GeDefense Titan

- New Titan control-center page with posture, ingress timeline, quarantine, owner policy and evidence.
- Trust and authorization model (`AUTHORIZED`, `TOLERATED`, `UNEXPECTED`, `COMPROMISED`).
- Native Windows sensor, persistence/security inventory, signed evidence chain, quarantine vault, owner policy and response, native notifications.
- Explicit honest limits and branding update to **GeDefense Titan**.

### 5.0.0 — Configurable security fabric

- Server-side settings engine with 55 validated controls across Defender, firewall, hardening, MHX, Kinetic, Threat Intelligence, startup and notifications.
- Custom protection profiles with server-enforced floors and confirmation phrases.
- Deep Defender telemetry with real measured values and explicit `null` for non-measurable fields.
- Validated Defender/firewall/hardening apply paths with evidence, baseline and rollback support.
- MHX XDR auto-response, notifications and application allow/deny via real Windows Firewall program rules.
- Threat Intelligence page with per-feed authority and generation verification; Kinetic Defense remains active with reboot re-verification.
- Startup gate only when needed, service self-healing supervisor, hardening/audit/evidence UX improvements.
- New V5 "Glass 2100" console composition, native Windows block toasts, WFP cardinality and sync speed fixes, false-positive tuning.
- New native Win32 installer design with measured progress, phase rail and trust sidebar.

---

## What we fixed in security hardening

The deep audit (`VGT-AUDIT-20261022-GEDEF-512`) covered 48 findings across HTTP/API/authentication, data plane (parsers, files, evidence, Titan, threat intelligence), host privileges/services/MHX/WFP/hardening and the PowerShell engine. Across 5.1.3 and 5.1.4:

- **Fixed locally:** authentication and scopes, session/rotation/replay, token and secret ACLs, bootstrap secret removal from browser arguments, evidence-chain and checkpoint handling, feed TTL/authority verification, vault/retention/ADS/reparse hardening, PID-reuse-safe process handling, single-instance authority, browser Authenticode verification, installer downgrade guard, release-channel hygiene, SBOM/provenance/sidecar chain, handoff hygiene and repository cleanliness.
- **Mitigated with documented residual risk:** the Center host remains an external Chromium kiosk without an embedded renderer; browser paths are machine-wide, administrator-writable, reparse-free and Authenticode-verified.
- **External blockers, owner-accepted, not claimed as pass:** public code-signing identity with RFC 3161 timestamp and CRL/OCSP revocation, clean-host trust provisioning, an externally anchored anti-rollback channel and VGT feed signing keys. The feed verifier remains fail-closed `UNCONFIGURED` until keys are provisioned.
- **Verification:** full release gate (Go race with `vgt_bundle`, Go vet, govulncheck-binary, PowerShell parse, frontend security invariants, SBOM, provenance, distribution hygiene, installer safety, release channel, sidecar binding and publish gates), deterministic source archive, signed installer build, offline publish verification, and unit/integration tests for every touched package.

---

## Architecture

```text
GeDefenseCenter.exe / GeDefenseTray.exe        operator surfaces (unprivileged)
        │  operator broker session (Windows process token verified)
        ▼
127.0.0.1:17831                                authenticated loopback API
        │
        ▼
VGTGeDefense Windows Service (LocalSystem)     sovereign control plane
        ├── Defender / ASR / Firewall / WFP / App Control / Hardening
        ├── MHX EDR/XDR process and network correlation
        ├── Threat Intelligence feeds and WFP generation
        ├── Kinetic Defense burst correlation
        ├── Native traffic + local GeoIP/ASN map
        ├── Titan sensor, quarantine, owner policy and signed evidence
        └── HMAC/SHA-256 evidence ledger + Ed25519 checkpoints
```

- **Zero external Go modules.** Only the Go standard library and small internal Win32 wrappers.
- **Local host UI.** The embedded web UI is served locally; the native Win32 host launches an installed Chromium browser in kiosk mode (external renderer, no embedded WebView2).
- **No runtime CDNs.** All UI assets, the map geometry and the GeoIP/ASN CSV are local.

---

## System requirements

- Windows 11 x64 (build 22621 or newer recommended).
- Local administrator rights for installation and policy configuration. Center and Tray run in the operator's unprivileged user context.
- Windows PowerShell 5.1 x64.
- A locally installed Chromium browser (Edge, Chrome or Brave) for the Center UI.
- Optional: local GeoIP/ASN CSV (`data/geoip.csv` plus `.sha256`) for the map; without it the map reports "not loaded" and the rest of the product keeps working.

## Installation

1. Download `GeDefense-Setup-x64-v5.3.0.exe` from the [releases page](https://github.com/visiongaiatechnology/gedefensewin/releases).
2. Measure and inspect the artifact:

   ```powershell
   Get-FileHash -Algorithm SHA256 .\GeDefense-Setup-x64-v5.3.0.exe
   Get-AuthenticodeSignature .\GeDefense-Setup-x64-v5.3.0.exe
   ```

   The installer is currently **self-signed**. `Get-AuthenticodeSignature` reports `Valid` only on hosts that already trust the VGT certificate; for everyone else the expected state is `NotTrusted`/`UnknownError`. The measured SHA-256 must match `SHA256SUMS.txt` and the `.sha256` sidecar of the release.
3. Run the installer as administrator. It installs the service, Center, Tray, hardening/XDR assets and the evidence/Titan runtime data root.
4. Start the Center. Center and Tray obtain short-lived operator sessions through the loopback broker; the long-lived master token is a SYSTEM/Administrators-only break-glass credential.
5. Open the **Protection Center** and follow the readiness guidance. Defensive default is `OBSERVE_ONLY`; sharp Kinetic correlation (`ARMED_TI_CORRELATION`) requires explicit operator confirmation.


### First-run setup

On the first Center start after installation or update, the **first-run setup
assistant** opens until setup has been completed server-side. It guides the
operator through four steps: use case, recommendation, activation and
verification:

1. **Use case:** personal PC, business/office, server/high-risk or
   developer/build.
2. **Recommendation:** **Enterprise Balanced** is the default for personal and
   business use; **Isolation** additionally disables USB storage and RDP and is
   only appropriate for matching server/high-risk environments. The protection
   level table explains what `OBSERVE`, `BALANCED` and `ISOLATION` mean.
3. **Activation:** hardening profile, integrity monitor, Titan policy and MHX
   policy reconciliation are applied through the existing operator APIs. The
   assistant exposes errors and rejected preconditions; it never pretends that
   an apply succeeded.
4. **Verification:** setup can only be completed after Defender, ASR (11/11
   blocking), Controlled Folder Access, firewall, protection policy and the
   integrity monitor are actually verified.

The completion marker is stored server-side and authenticated. A different
browser, machine or session does not reset it; a new program version may request
the setup again. The wizard is not an authorization bypass: mutations remain
bound to the local operator session and the server-side confirmation phrases.

### Important operating notes

1. **Local sovereignty:** the control plane runs on loopback only; no cloud control plane and no silent third-party telemetry.
2. **Defensive default:** Kinetic Defense starts in observe-only mode.
3. **Windows audit policy:** inbound WFP block telemetry (event ID 5157) requires the Windows Filtering Platform audit policy to be enabled.
4. **Uninstall:** exports relevant evidence first, then removes managed protection policies as far as configured.

### UI languages

The Center UI is available in **German, English, Russian and Simplified Chinese**. The language is detected automatically from the system/browser language and can be changed at any time via the language switcher in the header. The choice is remembered locally (cookie, no external service). The README is available in the same four languages.

---

## Local sovereignty and privacy

- No external cloud control plane.
- No silent telemetry to third parties.
- Threat-intel feeds are fetched from their documented upstream sources; feed content is not sent anywhere else.
- GeoIP/ASN attribution is local CSV-based; IP addresses are not sent to external geo services.
- Evidence and quarantine data stay on the local host and are protected by ACLs; evidence exports are explicit operator actions.

---

## Verification and trust

- **Release gates:** Go race suite (including `vgt_bundle`), Go vet, `govulncheck -mode=binary` (0 reachable vulnerabilities), four Windows builds, PowerShell 5.1 parsing, frontend security invariants, CycloneDX SBOM, deterministic source archive, unsigned-local provenance, distribution hygiene, installer safety, release-channel hygiene, sidecar binding and offline publish verification.
- **Artifacts:** signed installer, `.sha256` sidecar, JSON release sidecar (measured bytes/hash/signer plus SBOM/provenance bindings), artifact SBOM, provenance and `SHA256SUMS.txt`.
- **Signature status:** the current installer is signed with a **local self-signed identity** (no public CA, no RFC 3161 timestamp, no online revocation). This is a beta limitation and a documented external blocker — **no public trust is claimed**.
- **Provenance:** deliberately unsigned-local; it proves build inputs/hashes and reproducibility of the source archive, not remote attestation.
- **CI:** `.github/workflows/security-gate.yml` runs the release gate on a Windows runner when the repository is tagged and CI is available.

---

## Licenses and attribution

### Software license

GeDefense Windows source code and documentation are licensed under the **GNU Affero General Public License v3.0 only (AGPL-3.0-only)** — see [LICENSE](LICENSE). Names, logos and visual brand assets are covered by [TRADEMARKS.md](TRADEMARKS.md); third-party components are listed below and in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), [LICENSE-MATRIX.md](LICENSE-MATRIX.md) and [DEPENDENCIES.md](DEPENDENCIES.md).

### World map geometry — jsVectorMap (MIT)

The bundled local world map geometry (`src/GeDefense/windows/internal/server/web/world-merc.js`, `world-merc.js`) is taken from the open-source **jsVectorMap** project and matches its Mercator world map, version **1.7.0**:

- Project: [themustafaomar/jsvectormap](https://github.com/themustafaomar/jsvectormap)
- Map file: [world-merc.js 1.7.0](https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js)
- License: [MIT License](https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE) · Copyright © 2020 Mustafa Omar
- Full license text: [LICENSES/jsVectorMap-LICENSE](LICENSES/jsVectorMap-LICENSE)

The local file is wrapped as an ES module; the jsVectorMap runtime library itself is not used.

### GeoIP/ASN data — iplocate and DB-IP (attribution required)

The optional local CSV (`data/geoip.csv`, delivered in the installer payload, not in the public Git) merges public IP-to-country/IP-to-ASN data. Attribution is required for redistribution and derivative works:

- **ASN data:** [iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases) — public IP-to-country and IP-to-ASN databases, licensed under **CC BY-SA 4.0** ([license](https://creativecommons.org/licenses/by-sa/4.0/)). A concrete example: the network `1.0.4.0/22` is listed with ASN `38803` and organisation `Gtelecom Pty Ltd`, matching the bundled CSV. Source attribution: © iplocate/ip-address-databases contributors, CC BY-SA 4.0.
- **Geolocation data (prior/combined base):** DB-IP Lite — [DB-IP](https://db-ip.com), **CC BY 4.0** ([license](https://creativecommons.org/licenses/by/4.0/)).
- **Status:** the exact upstream snapshot date and completeness of the bundled CSV are not independently confirmed; the SHA-256 sidecar was corrected against the actual bytes. Details: [GEOIP_LICENSE_AND_DEPLOYMENT.md](GEOIP_LICENSE_AND_DEPLOYMENT.md).
- The data grants no enforcement authority; country/ASN describe approximate network registration origin, not a person's physical location.

### Other third-party material

- Go standard library and toolchain: Go/BSD license; pinned toolchain hash in [TOOLCHAINS.lock](TOOLCHAINS.lock), not redistributed.
- Microsoft Windows, Defender, Firewall/WFP and App Control: Microsoft license; not part of the repository.
- Threat-intelligence feeds (Feodo Tracker, Spamhaus DROP, FireHOL, CINS, blocklist.de, Emerging Threats, IPsum, Tor exit nodes): provider terms apply; snapshots are not bundled. See [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md).
- Windows PowerShell 5.1: Microsoft platform component, not redistributed.

---

## Build from source

Requirements: Windows 11 x64, Windows PowerShell 5.1 x64, Go **1.26.10** (see `TOOLCHAINS.lock`) and a C compiler suitable for the Go race detector.

```powershell
$env:GOTOOLCHAIN = 'go1.26.10'
# 1) deterministic source archive + SOURCE-MANIFEST
& .\build\Build-SourceRelease.ps1
# 2) full release gate + signed payload/installer + SBOM/provenance/sidecar/SHA256SUMS
& .\build\Build-GeDefenseStandalone.ps1
# 3) offline publish verification (no Git/VCS required with the explicit override)
& .\build\Publish-GitHubRelease.ps1 -VerifyOnly -AllowMissingVcs
```

The signing identity must be provisioned in the build account's certificate store (private key, code-signing EKU); `certificates/release-thumbprint.txt` references it by thumbprint only. Private keys are never committed. See [docs/BUILDING.md](docs/BUILDING.md).

---

## Feedback and contributing

- Bug reports, false-positive reports and feature requests: [GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues).
- Security disclosures: please follow [SECURITY.md](SECURITY.md) — do not publish exploitable details before a fix is available.
- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). A [Contributor License Agreement](CONTRIBUTOR-LICENSE-AGREEMENT.md) applies.

**Thank you for testing the GeDefense Titan beta.** Reproducible feedback — including honest failure reports — is what makes the next release better.
