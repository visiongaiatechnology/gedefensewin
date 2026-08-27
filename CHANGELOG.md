# Changelog

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

