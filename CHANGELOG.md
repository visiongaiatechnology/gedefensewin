# Changelog

## [4.1.0-beta.1] - 2026-09-19

### Added
- Sovereign 9-feed Threat Intelligence Core with explicit `BLOCK`, `CORRELATE_ONLY`, and `ANNOTATE_ONLY` policy semantics.
- Last-known-good per-feed generations, strict feed token validation, bounded HTTPS ingestion, anti-SSRF DNS resolution, catastrophic-shrink protection, and immutable lock-free lookup generations.
- Windows Firewall generation enforcement using Dynamic Keyword Addresses where supported, with verified static-rule fallback and fail-closed generation promotion.
- WFP Security Event 5157 telemetry correlated back to owning PID, process analysis, feed attribution, and MHX Attack Stories.
- Separate desired versus active firewall-generation verification exposed in MHX status and Sovereign readiness.
- Authenticated Protected-Network policy with exact CIDR subtraction before WFP publication, operator-confirmed API/UI updates, and immutable policy generations.

### Security
- Tor is strictly annotation-only; CINS Army, blocklist.de, Emerging Threats, IPsum and FireHOL remain correlation-only; only Feodo and Spamhaus DROP v4/v6 can authorize network blocking.
- Network IOC matches still never grant process termination authority without independent MHX host-response authority and PID/creation-time/image revalidation.
- Feed cache and enforcement snapshots are atomically replaced and bounded; malformed, private, reserved, metadata-service, oversized, HTML, redirecting, or catastrophically truncated feed data is rejected.
- Protected management networks remain visible to XDR attribution but cannot create Threat-Intel-derived host-response eligibility; stale WFP blocks against a protected prefix are explicitly surfaced.
- Threat-Intelligence state is ACL-isolated to SYSTEM/Administrators; protected-network policy files are HMAC-SHA-256 authenticated.
- Static firewall fallback is hard-capped at 25,000 indicators to prevent rule-explosion resource exhaustion.

### Changed
- MHX engine version advanced to 7.1.
- Threat-intelligence synchronization is restart-aware and reconciles cached generations back into Windows Firewall before the next scheduled download.
- XDR and Network UI now expose feed policy classes, per-feed state, WFP block telemetry, and generation verification.

## [4.0.0-beta.1] - 2026-09-18

### Generation 4

- externe Go-Modulabhängigkeiten vollständig entfernt; Win32-, Tray-, Service-, Netzwerk- und Launcher-Pfade intern gekapselt
- Control Plane in getrennte Trust- und Handler-Domänen modularisiert
- bounded Replay-, Session-, Bootstrap- und Rate-State eingeführt
- native TCP→Owning-PID-Telemetrie und Threat-Intel-Prozesskorrelation ergänzt
- Attack Stories für Prozess-, Netzwerk- und Threat-Intel-Evidenz ergänzt
- Prozessreaktion und Netzwerk-Korrelation gegen PID-Reuse mit Creation-Time-/Image-Revalidierung gehärtet
- Threat-Intelligence-Parsing, Prefix-Index, Feed-Grenzen und lokale/reservierte Netzfilterung gehärtet
- Integrity-Lifecycle, Reparse-Handling, Mutation-during-hash-Erkennung und bounded State gehärtet
- modernes Ice-Blue-Glassmorphism-UI mit Protection Center, Guided Activation, XDR- und Netzwerkansichten eingeführt
- Monitor → Guarded → Sovereign als serverseitig validierter Aktivierungsfluss vereinheitlicht
- XDR-Forensik auf Hash-/Metadaten-Evidenz statt roher verdächtiger Command Lines umgestellt
- SBOM, Lizenzmatrix, Dependency-Dokumentation und Release-Gates auf Zero-Go-Dependency aktualisiert
- Windows-Policy-Mutationen global serialisiert und Protection-Health serverseitig verifiziert
- Threat-Intel-Enforcement in den Feed-Health-State gekoppelt; fehlgeschlagene Firewall-Verifikation markiert Generationen als `STALE`
- Installer-Bootstrap auf `ExecutionPolicy AllSigned` gehärtet und offizielle Build-Toolchain auf Go 1.27.1 gepinnt
- privilegierte PowerShell-Aufrufe auf den validierten `%SystemRoot%\System32`-Pfad festgelegt; kein `PATH`-Fallback
- Sovereign-Allow-Änderungen an nachgelagerte App-Control-Kernelverifikation gekoppelt; Verifikationsfehler degradieren den Protection-Health-State
- deterministischen Source-Release-Builder mit Source-Manifest, Reparse-/Workspace-Grenzen und festen Zeitstempeln ergänzt

Alle wesentlichen Änderungen werden in dieser Datei dokumentiert. Das Format orientiert sich an Keep a Changelog; Versionen folgen semantischer Versionierung, soweit Windows-Richtlinienänderungen dies zulassen.

## [2.3.2] - 2026-08-27

### Added

- modernes Live-Security-Dashboard
- MHX XDR 6.0 mit EncodedCommand-Dekodierung und Kontextanalyse
- Monitor-, Guarded- und Sovereign-Schutzmodus
- 12-Stunden-Threat-Intelligence und atomare Firewall-Regeln
- SHA-256-Integrity-Scanner mit 12/24-Stunden-Intervall
- zwölf live messbare und einzeln härtbare Windows-Komponenten
- SafetySys-Auto-Audit beim Öffnen des Tabs
- native WebView2-Anwendung und Systemtray

### Fixed

- null-sichere API-Listen und MHX-Rendering
- persistenter Guarded-Zustand vor Dienststart
- stabiler CIM-Prozessprovider mit Heartbeat
- priorisierter Enrichment-Pfad für EncodedCommand
- transaktionale App-Control- und ACL-Fehlerbehandlung

### Security

- Loopback-only Control Plane
- kurzlebiger Bootstrap und Replay-Schutz
- HMAC-SHA-256-Evidenzkette
- signierbarer, reproduzierbarer Standalone-Payload

