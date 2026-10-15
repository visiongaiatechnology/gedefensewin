# GeDefense 4.1.2 — Verification, 2026-10-15

Scope: repair window ownership/chrome and add automatic startup synchronization with an evidence-based internal health check.

## Implemented

- Launcher-owned native Win32 host; Chromium renderer selected solely by the PID that the launcher started. No global title matching, Explorer selection, fixed pixel clipping, stale-profile deletion or browser termination by command-line substring.
- Single bounded command queue. The service does not call desktop Win32 APIs. State reads are read-only. Disconnected controls fail explicitly; acknowledgements validate the JSON shape and state enum.
- Startup dialog after authentication; configured policy reconciliation, conditional Threat Intelligence/firewall synchronization, fresh read-only Windows audit and seven authoritative checks. Retry, background operation, keyboard focus, narrow layouts and reduced motion are supported.
- Initial audit failures no longer fabricate enabled Defender/Firewall values. Policy and feed failures return opaque responses; internal causes remain in the service log.
- Go toolchain patched from 1.26.4 to 1.26.9 after the vulnerability scan. The official Windows amd64 archive SHA-256 is pinned in TOOLCHAINS.lock. No external production Go modules were added.

## Passed

- Full Go tests and race detector, go vet, gofmt.
- Ten shuffled repetitions of the Go suite.
- Staticcheck v0.8.2.
- govulncheck with Go 1.26.9: no vulnerabilities found.
- Opt-in real Win32/Chromium integration with Edge and Chrome, including race detector: borderless client dimensions, parent ownership, maximize, restore and minimize.
- Six isolated browser fixtures: 1440px desktop, 800px narrow desktop, 390px mobile, degraded Defender, failed policy synchronization and malformed health response. Retry and dialog dismissal also exercised. Screenshots inspected.
- Health endpoint integration: authentication required, fresh Audit used instead of cached Posture, corrupted on-disk ledger produces attention, no false green.
- Existing Windows PowerShell 5.1 release gate: four Windows binaries, race tests, vet, script parsing, frontend security and zero production Go dependencies.

## Limits and remaining release gates

- A clean install/upgrade on a separate Windows VM has not been run. The active installed security configuration was not replaced during verification. The browser fixtures use explicit test data, not live security claims.
- Additional golangci-lint v2.14.0 default scan is not clean: 53 findings (50 errcheck, 3 staticcheck quick-fix suggestions). The log contains legacy cleanup/Win32 return handling plus findings in touched interop functions; the complete repository lint gate must not be represented as passed.
- No parser changes were made; no new fuzz campaign was needed for this scope. Existing bounded/hostile-input regression tests were included in the full suite.
- The original SOURCE-MANIFEST.sha256 and FULL_SOURCE_SHA256.txt describe the imported source archive. They are not a checksum of this edited workspace. The new installer has its own verified release JSON and signed payload catalog.

## Classification and upgrade path

GOLD for the delivered change, with the functional regression scope above. A PLATIN/DIAMANT release claim is withheld until the full repository lint findings are resolved with semantic Win32 return checks and durability-aware cleanup handling, and an isolated clean-install/upgrade confirms the signed installer, service bootstrap, window controls and actual startup health transitions end to end.

## Reproduce

- In src/GeDefense/windows: go test -race ./..., go vet ./..., go test -shuffle=on -count=10 ./..., go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./..., govulncheck ./...
- Browser fixtures: node test/startup-health.browser.cjs (Playwright provided through the configured workspace runtime; CODEX_NODE_MODULES may override its package directory).
- Native integration: set GEDEFENSE_NATIVE_UI_TEST=1 and GEDEFENSE_NATIVE_BROWSER to an installed Chromium executable, then go test -race ./internal/winframe -run TestNativeBrowserHost -count=1.
- Signed package: use Windows PowerShell 5.1, set GOTOOLCHAIN=go1.26.9 and run build/Build-GeDefenseStandalone.ps1 with the already provisioned signing certificate. No new certificate trust is needed.

Evidence: work/verification contains the build log, vulnerability scan, additional lint output and browser screenshots.

## Final artifact verification

- release/GeDefense-Setup-x64-v4.1.2.exe: 26337592 bytes.
- SHA-256: 3FE80632524897D9DF8D97FDCB9393CF5138F6052F063C351DFB64B7B4E24A2A.
- Installer, service, Center, Tray and payload catalog all verified with Valid Authenticode status and the provisioned release signer.
- The installer embedded ZIP contains 31 entries; its three executable payloads exactly match the signed staging binaries.
- The service binary contains the exact final startup-health.js, startup-health.css, window-controls.js, index.html and app.js source bytes.
- Binary-mode govulncheck of the signed service: no vulnerabilities found.
