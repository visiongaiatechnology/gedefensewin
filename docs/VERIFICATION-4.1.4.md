# GeDefense Windows 4.1.4 — WFP-Telemetrie-Hotfix

## Observed installed state

Before the upgrade, read-only authenticated status of installed 4.1.3 showed WFP DEGRADED, cumulative count 30, kinetic audit OFFLINE and a verified Threat-IP firewall generation. The service was running; only one PowerShell child remained. WFP degraded records existed in the evidence ledger. The original bridge exit cause is not exposed by 4.1.3. This process is not elevated, so direct effective audit-policy and Security-log inspection could not establish their current state.

## Scope

The source repair adds WFP bridge supervision, capped retry delay, joined watchdog/process cleanup, a preserved in-memory record cursor, receipt-based sensor health, strict wire validation and bounded stderr. Real event times remain unchanged. Access/query errors cannot masquerade as an empty successful query. The startup health check rejects an offline WFP bridge even with historical blocks.

## Qualification

Executed tests and artifact validation are recorded below. After installation of 4.1.4, authenticated live status reported the service running, WFP polling active and five newly ingested block events. This confirms a recovered reader and event delivery. It does not verify the effective Windows audit policy or full ingress coverage. Isolated fixtures and fuzzing do not replace VM install/upgrade qualification. Overall qualification remains GOLD pending isolated install/upgrade and independent review.

## Passed

- Full Go race suite, go vet, gofmt and Staticcheck v0.8.2.
- Full unlimited golangci-lint v2.14.0 scan: 0 issues, without added exclusions or suppressions.
- Native Windows PowerShell fixtures distinguish no matching events from access failure; failed queries cannot announce READY. Syntax and strict wire boundaries checked.
- Historical event times preserve original correlation time while health uses current receipt time; duplicate delivery and cancelled delivery/cursor commit checked.
- Retry recovery, cancellation during long backoff, watchdog termination/reaping and bounded stderr checked. WFP regression tests repeated ten times under race detection with shuffled order.
- WFP wire fuzzer: 30 seconds, 143,398 executions; no failure.
- Existing Windows PowerShell 5.1 release gate and signed standalone build passed with Go 1.26.9 and bounded compiler concurrency.
- Source and signed-service binary govulncheck: no vulnerabilities found.
- Installer, service, Center, Tray and catalog Authenticode status: Valid. Embedded ZIP has 38 entries; version and all three executable payloads match signed staging. The rebuilt service contains the new WFP query script.

## Release artifact

- Installer: release/GeDefense-Setup-x64-v4.1.4.exe
- Bytes: 26418488
- SHA-256: 8031CB67DC330B2D218F8FB714A3BB9D89BABF4CFEAE54219DCFDCBC6A296BCE
- Manifest and .exe.sha256 sidecar provided.

The user installed the signed 4.1.4 installer. Read-only authenticated status confirmed the WFP reader recovered and five new events arrived. No audit-policy or firewall change was performed. The live audit policy remains unverified.

Event-query API contract: [Microsoft Get-WinEvent, Windows PowerShell 5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1).
