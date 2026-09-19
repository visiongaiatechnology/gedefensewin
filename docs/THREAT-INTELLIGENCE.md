# VGT GeDefense Windows 4.1 Threat Intelligence

// STATUS: DIAMANT VGT SUPREME

## Security invariants

The Threat Intelligence subsystem is a local control plane. Feed ingestion, policy classification, userspace correlation, Windows Firewall enforcement and XDR evidence are isolated responsibilities. A feed entry is never permitted to inherit more authority than the catalog assigns to its source.

| Feed | Action |
|---|---|
| Feodo Tracker C2 | `BLOCK` |
| Spamhaus DROP IPv4 | `BLOCK` |
| Spamhaus DROP IPv6 | `BLOCK` |
| CINS Army Badguys | `CORRELATE_ONLY` |
| blocklist.de All | `CORRELATE_ONLY` |
| Emerging Threats Block IPs | `CORRELATE_ONLY` |
| IPsum Level 1+ | `CORRELATE_ONLY` |
| FireHOL Level 1 | `CORRELATE_ONLY` |
| Tor Exit Nodes | `ANNOTATE_ONLY` |

If a prefix exists in several feeds, effective authority is the maximum of those explicitly assigned actions while complete feed attribution is preserved. `ANNOTATE_ONLY` never enters an enforcement snapshot. `CORRELATE_ONLY` may strengthen an XDR story but never enters a Windows Firewall block generation.

## Data path

```text
HTTPS feed fetch
  -> host/DNS address validation
  -> bounded response body
  -> format parser
  -> strict IP/CIDR validator
  -> per-feed last-known-good snapshot
  -> immutable ThreatIndex generation
       |-> correlation / annotation -> MHX/XDR
       `-> BLOCK projection -> enforcement snapshot
                              -> WFP / Windows Firewall generation
                              -> generation verification
                              -> Security Event 5157 -> PID correlation -> Evidence
```

## Feed ingestion

- HTTP redirects are rejected.
- TLS 1.2 or newer is required.
- DNS answers are resolved before dialing and private, loopback, link-local, multicast and protected address ranges are rejected.
- Response headers and bodies are bounded.
- HTML error bodies are rejected.
- IP/CIDR tokens accept only hexadecimal digits, decimal dots, colons and `/`, are parsed with `net/netip`, canonicalized, deduplicated and bounded.
- Private, loopback, link-local, multicast, unspecified, carrier-grade NAT, documentation/test networks, cloud metadata endpoints and unsafe overly-broad prefixes are rejected.
- A feed collapsing below 10% of a previously validated generation is rejected once the previous generation contained at least 100 indicators.
- A failed source retains its independently integrity-verified last-known-good generation in memory and on disk.

## Generations and enforcement

The userspace ThreatIndex has a SHA-256 generation fingerprint. The `BLOCK` projection has a second SHA-256 enforcement fingerprint. Windows Firewall is not considered synchronized until the firewall transaction returns the exact requested enforcement generation and indicator count with a non-zero verified rule/shard set.

MHX exposes both `desiredGenerationSha256` and `activeGenerationSha256`. Sovereign readiness requires them to match. A daemon restart reconstructs the enforcement snapshot from validated source caches and reconciles the active firewall generation without forcing an unnecessary remote feed download.

On Windows versions exposing NetSecurity Dynamic Keyword Addresses, GeDefense shards block prefixes into bounded dynamic address objects and binds each object to one inbound and one outbound block rule. A complete new generation is staged and verified before old VGT generations are removed. Cleanup failure leaves old and new block generations active and is reported as `VERIFIED_CLEANUP_PENDING`. If Dynamic Keyword Addresses are unavailable or staging fails, a bounded static-rule generation is used as the compatibility fallback.


## Protected Network Safety Plane

Windows Firewall block rules win over colliding allow rules. GeDefense therefore does not attempt to "override" a threat block with a second allow rule. Instead, the BLOCK projection is compiled before WFP publication:

```text
validated BLOCK union
  -> prefix compaction
  -> subtract authenticated protected management prefixes
  -> enforceable CIDR complement
  -> SHA-256 enforcement generation
  -> WFP transaction
```

A protected prefix never deletes Threat Intelligence from the userspace index. `Lookup()` still returns the original feed action and attribution, but marks the match as `protected`. MHX/XDR can therefore record that a protected management destination is listed by Feodo/Spamhaus without using that network match to create host-response eligibility. If a stale GeDefense WFP generation is observed blocking a newly protected destination, the event is surfaced explicitly as a stale protected-network block instead of being treated as a normal successful GeDefense enforcement event.

Protected-network policy invariants:

- maximum 256 operator prefixes; canonical CIDR union is compacted before persistence;
- IPv4 prefixes broader than `/16` and IPv6 prefixes broader than `/32` are rejected; `/0`, private, loopback, link-local, multicast, documentation/test and metadata-related ranges are rejected;
- the policy has an independent SHA-256 generation and an HMAC-SHA-256 authentication tag;
- policy mutation requires authenticated local API access, explicit confirmation, a bounded operator reason and a replay-protected request ID;
- compilation is bounded by the same 250,000-prefix WFP enforcement ceiling; a policy that would remove all blocking enforcement is rejected before persistence;
- the runtime intelligence directory is ACL-restricted to `SYSTEM` and local Administrators; dashboard operators use the localhost API instead of reading the policy key directly.

## XDR semantics

Allowed/observed connections are correlated through the native TCP owner-PID telemetry path. Blocked connections are observed through Windows Filtering Platform Security Event 5157. On Windows 11, `FilterOrigin` is captured when present; GeDefense-created firewall rules use deterministic `VGT-GeDefense-TI-*` rule identifiers so MHX can distinguish its own block origin from another WFP block.

A network IOC match alone never grants host-process termination authority. Process response remains gated by the existing MHX evaluator and anti-PID-reuse identity revalidation. Tor annotation can never authorize termination. Correlation-only feeds can enrich severity and attack stories but cannot independently create network enforcement.

## Persistent data

Default runtime root:

```text
%ProgramData%\VGT\GeDefense\mhx\intelligence\
  sources\<feed-key>.json
  threat-intelligence-enforcement.json
  protected-network-policy.json
  protected-network-policy.key
```

Source and enforcement snapshots are written through temporary files, flushed, closed and atomically replaced. Cache files are parsed with strict schemas and their canonical indicator lists are fingerprint-verified before use. The protected-network policy is additionally authenticated with HMAC-SHA-256 before it is accepted at startup.

## Verification gates

Source release verification includes:

```text
go test ./internal/threatintel
GOOS=windows GOARCH=amd64 go test -exec=/bin/true ./...
GOOS=windows GOARCH=amd64 go vet ./...
```

The Windows release gate must additionally execute the real Windows tests so the PowerShell parser, WFP audit configuration, NetSecurity Dynamic Keyword Address transaction, firewall fallback, Security Event 5157 ingestion and installed-service reconciliation are validated on the target OS.
