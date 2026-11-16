# GeDefense Inno Setup Installer

Branded Inno Setup 7 installer for GeDefense Windows 5.3.0.

## Why this installer exists

The previous Go installer delegates installation to a signed PowerShell bootstrap
started with `-ExecutionPolicy AllSigned`. On a fresh Windows installation the
self-signed VGT release certificate is not trusted yet, so the bootstrap cannot
run and users would have to import the certificate manually. The Inno installer
imports the embedded certificate itself — after the user accepts the license and
beta terms — and then runs the signed bootstrap with the correct 64-bit
PowerShell. No manual certificate handling is required.

## Build

1. Build the signed payload first:

   ```powershell
   .\build\Build-GeDefenseStandalone.ps1
   ```

2. Build and sign the Inno installer:

   ```powershell
   .\build\Build-InnoInstaller.ps1
   ```

   `-NoSign` skips signing for development. Inno Setup 7 must be installed
   (`ISCC.exe`); the script searches the usual per-user and per-machine paths.

Output:

- `release\GeDefense-Setup-Inno-x64-v5.3.0.exe`
- `release\GeDefense-Setup-Inno-x64-v5.3.0.exe.sha256`
- `release\GeDefense-Setup-Inno-x64-v5.3.0.json` (sidecar)

## Features

- Language selection at startup: German, English, Russian, Simplified Chinese.
- Per-language Beta Program Terms and Terms of Use (`terms/terms.<lang>.txt`).
- Beta-program and certificate-trust notice page after the license page.
- Left wizard branding with Sir QuackSec (dark Glass 2100 palette).
- Stable `AppId`, x64 install mode, admin privileges, upgrade support.
- The Inno uninstaller is wired to the signed GeDefense uninstall transaction;
  `UninstallDelete` removes the copied setup executable as well.
- The certificate import is explicit: accepting the beta terms on the license
  page constitutes consent; the notice page explains the trust-store change.

## Trust and distribution limits

The installer is Authenticode-signed with the self-signed VGT release certificate.
Windows will still show an “Unknown publisher” / SmartScreen warning on machines
that do not trust that certificate. That is expected for a self-signed beta build.
A publicly trusted code-signing certificate (OV/EV) is required for a warning-free
production release; the Inno installer is prepared for that (replace the signing
certificate in `certificates/` and re-run the build script).

The terms texts are product terms, not a substitute for a jurisdiction-specific
legal review.
