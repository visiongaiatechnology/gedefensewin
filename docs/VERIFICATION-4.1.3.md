# GeDefense 4.1.3 — Verification, 2026-10-15

## Delivered scope

- Removed the light native resize gutter: a solid product-color background brush replaces COLOR_MENU; DWM accent borders are disabled and no glass margin enters the client.
- Center starts maximized. Restore uses a centered rectangle at 92% width and 90% height of the nearest monitor work area. Negative monitor origins and different work-area sizes are covered.
- Full unbounded golangci-lint v2.14.0 scan: **0 issues**. The earlier 53-item output had hidden repeated findings; the full baseline was **92 findings** (89 errcheck, 3 staticcheck suggestions). No linter exclusions, suppressions or disabled checks were introduced.
- BOOL calls consult last-error only on failure. HRESULT calls inspect the signed HRESULT. Informational/VOID calls are documented locally. Ambiguous style/parent changes are verified through native postconditions.
- File/network-body close errors and temporary-file/staging cleanup failures are conserved in operation results. Atomic-rename cleanup tolerates a consumed temporary file. Tray event watching has bounded waits, cancellation and a join before handle release.
- The startup dialog prevents background scrolling.

## Passed

- Full Go test suite and race detector, go vet, gofmt; edited imports normalized with goimports.
- Full suite shuffled and repeated ten times.
- Staticcheck v0.8.2 over 28 enumerated packages.
- golangci-lint v2.14.0 with max-issues-per-linter=0 and max-same-issues=0: 0 issues.
- Source-mode and signed-service binary-mode govulncheck: no vulnerabilities found.
- Native Edge integration with two successive host lifecycles in one process; native Chrome integration; all under race detector.
- Native assertions: maximized initial state, complete client dimensions, renderer parent ownership, maximize/restore/minimize, exact dark gutter pixels after renderer attachment and restore.
- Visual inspection through computer-use of the isolated native host rendering the actual GeDefense HTML/CSS/JS with clearly labelled fixture data: dark edge and large restored window confirmed.
- Six browser scenarios: desktop, narrow desktop, mobile, degraded Defender, policy failure and malformed response; retry and dismissal exercised.
- Error-contract tests: stale Win32 last-error values cannot turn success into failure; failed BOOL/HRESULT values cannot become success; operation and close errors survive together; unexpected cleanup failures propagate; idle tray event watching cancels before resource release.
- Existing Windows PowerShell 5.1 release gate: zero external production Go modules, full race tests, vet, four Windows builds, PowerShell parsing and frontend checks.

## Signed artifact

- Installer: release/GeDefense-Setup-x64-v4.1.3.exe
- Version: 4.1.3; architecture x64; Go toolchain 1.26.9.
- Bytes: 26414392.
- SHA-256: 95E5284B898EE34793E407D5BF9EE4E6877143673FF3A1187F4C1461D6390B42.
- Authenticode: Valid for installer, service, Center, Tray and payload catalog, all with the provisioned release signer.
- Installer embedded ZIP: 38 entries. All three embedded binaries exactly match signed staging binaries. The service embeds the final startup CSS byte for byte.

## Scope and qualification

The requested window repair and complete lint cleanup are implemented and verified. Overall release classification remains conservatively GOLD pending the separate Windows VM clean-install/upgrade qualification documented for 4.1.2; resolving the lint gate does not prove an installation that was not performed. The path to full qualification is now the isolated install/upgrade and real service/bootstrap/health transition exercise. No requested code implementation remains.

The active installed security service was not replaced. Test fixture health results are not live security measurements. Original source-archive checksum files remain historical; the new release JSON and signed payload catalog verify this installer.

## Evidence and API contracts

Local build logs, browser images and baseline captures are retained in the authoring workspace and intentionally excluded from the public repository. The tests and reproduction instructions are included in source.

Class brush lifetime follows [Microsoft WNDCLASSEXW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassexw): Windows releases a registered class background brush on unregister. A pre-registration failure still releases the brush directly.

Window visibility/state checks follow [Microsoft ShowWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow). Its return describes previous visibility, so state changes are checked through observable native state.

Border suppression follows [Microsoft DWMWINDOWATTRIBUTE](https://learn.microsoft.com/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute). Optional attributes absent on older Windows builds are handled separately from supported API failures.

## Publication packaging

The final publication rebuild includes LICENSE, NOTICE, THIRD-PARTY-NOTICES.md, GEOIP_LICENSE_AND_DEPLOYMENT.md and LICENSES in the signed payload. Installation copies these notices to the installation root. Signed PowerShell sources are stored without Git newline conversion to preserve Authenticode bytes. The browser fixture resolves Playwright through normal Node resolution or an explicit CODEX_NODE_MODULES directory; no personal machine path is embedded. All six browser cases and seven telemetry UI tests were rerun successfully.

Final publication installer: 95E5284B898EE34793E407D5BF9EE4E6877143673FF3A1187F4C1461D6390B42; 26414392 bytes. All embedded license/notice bytes and the GeoIP data hash were verified.

The final clean publication checkout passed the Windows PowerShell 5.1 release gate (race suite, vet, four Windows builds, version/dependency/frontend/PowerShell checks). An initial concurrent compile exhausted Windows memory; rerunning with GOMAXPROCS=2 and GOFLAGS=-p=2 passed without reducing test coverage. The rebuilt signed service also passed binary-mode govulncheck.
