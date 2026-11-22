# IPA Inspector

A native iOS 17+ workbench for static analysis and security assessment of iOS
apps (.ipa files). Everything runs **on device** — no analysis data, IPA bytes
or secrets ever leave the phone, and there is no code path that uploads them.

## What it does

| Module | Capability |
|---|---|
| Overview | Dashboard built only from real analysis results (identity, sizes, hashes, counts, findings by severity) |
| File Explorer | Full IPA directory tree, per-file metadata (type, size, compression, permissions, SHA-256), text/plist/JSON/XML/strings/image previews, hex viewer with byte/ASCII columns, hex+text search, jump-to-offset — streamed, never loading whole files |
| Mach-O | Thin / FAT / FAT64 parsing: headers, load commands, segments & sections, linked libraries, runtime paths, UUIDs, encryption status |
| Swift Metadata | `__swift5_*` section inventory, mangled type names, reflection strings (honest `estimated` status; encrypted binaries reported blocked) |
| Objective-C | Class/method/category name extraction from `__objc_*` sections with section sizes as evidence |
| Symbols | LC_SYMTAB parsing: imported / exported / local symbols per architecture |
| Strings | Streaming strings extraction from unencrypted binaries |
| Dependencies | Embedded frameworks and extensions, Apple frameworks linked, hosts referenced, SDK inventory |
| Security | 20+ OWASP MASVS/MASTG-mapped static checks with severity, confidence, evidence, precise source location, remediation and honest evidence status |
| Secrets | Pattern + entropy+context credential detection, allowlisted examples, masked everywhere, local-only reveal, file+offset provenance |
| SDK Inventory | Fingerprinting from paths/frameworks/link tables, versions only from bundle metadata, duplicate-framework and suspicious-rename detection, **no fabricated CVEs** |
| Signing | embedded.mobileprovision parsing (team, expiry, devices, distribution), entitlements, signature states distinguishing unsigned / blob present / structurally checked / cryptographically verified (never claimed) |
| Reports | JSON (complete), PDF (hand-rolled writer), CSV (findings/symbols/components), TXT summary, and the full `IPAInspector-Analysis-Report` ZIP package with manifest and completeness metadata |
| App Store listing | Public iTunes Lookup metadata from a store link: identity, versions, size, ratings, description, privacy-policy URL, storefront support. A store link never provides the binary — every binary-level section is reported `blocked` rather than faked |

## Large-IPA pipeline (v0.2.0)

Imports up to and beyond 1 GB are designed in, not bolted on:

* **Staged copy** (`IPAStager`) — the imported file is copied out of the
  document-picker sandbox in 4 MiB chunks on a background queue, with live
  progress and cancellation. The UI never blocks and the IPA never doubles in
  memory. Free storage is checked first against a conservative estimate
  (copy + capped expansion + margin); the failure message names the fix.
* **Streaming extraction** (`DeflateExtractor` + `ZipArchive.streamRawData`) —
  stored entries stream to disk chunk by chunk; deflated entries decompress
  through ZIPFoundation straight into a pre-created file handle. Nothing is
  ever buffered whole, so peak memory stays at one chunk regardless of entry
  size. Partial output is removed on failure, and a written-size mismatch is
  reported instead of silently kept.
* **Bounded scans** — binaries over the scan cap are hashed and inventoried
  but not string-scanned; text resources over 8 MB are skipped for secrets;
  the archive plan caps entries (500k), per-entry size (2 GB), total size
  (4 GB) and compression ratio (2000:1, zip-bomb guard).

## Architecture

```
Sources/IPAKit/     Engine — pure Foundation, runs and tests on Linux AND iOS
  ├─ IPAAnalyzer        ZIP safety policy + streaming extraction pipeline
  ├─ IPAStager          Security-scoped staged copy, storage guard, progress
  ├─ DeflateExtractor   Chunk-by-chunk deflate streaming via ZIPFoundation
  ├─ BundleInspector    Info.plist, permissions, ATS, profile, privacy manifests
  ├─ MachO              Mach-O/FAT parser + symbol table + section access
  ├─ ZipArchive         Bounds-checked central directory + extraction plan
  ├─ AnalysisEngine     Async staged façade (progress, cancellation, caches)
  ├─ SecurityAssessor   MASVS/MASTG rules engine
  ├─ SecretScanner      Pattern + entropy+context detection, masking
  ├─ StructureAnalyzer  Components, versions, compatibility
  ├─ ProvisioningParser Profile + signature states
  ├─ FairPlayDetector   Per-slice cryptid/cryptoff/cryptsize reporting
  ├─ CrossBinarySearch  Unified search index + history
  ├─ DashboardProvider  Real-data aggregation
  ├─ ReportExporter     JSON / CSV / TXT / PDF writer
  ├─ ExportPackager     Complete-analysis ZIP with manifest
  ├─ MCPCore            Optional real JSON-RPC 2.0 tool server (no fake AI)
  └─ …
App/                SwiftUI layer (iOS only) — 12-module navigation, design system
Tests/IPAKitTests/  105 tests incl. fixture builder (synthetic IPA/Mach-O/ZIP)
```

## Build & test

```bash
# Logic tests (Linux or macOS)
swift test

# iOS app
brew install xcodegen
xcodegen generate
xcodebuild -project IPAInspector.xcodeproj -scheme IPAInspector \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" build
```

## CI

`.github/workflows/build.yml`:
1. **logic-tests** — full suite on ubuntu-24.04 + Swift 6.0.1
2. **discover-toolchain** — picks the newest Xcode present on the runner
3. **ios-build** — xcodegen + unsigned build + IPA structure validation
4. **release** — publishes the IPA as the stable asset **`unsigned-latest.ipa`**
   under the moving tag `unsigned-latest` (stable download URL, SHA-256 in the
   job log).

## Honesty rules (enforced in code)

* Every finding carries an evidence status: verified / detected / estimated /
  blocked / not found. Suspicion is never labelled vulnerability.
* Encrypted (FairPlay) slices produce *blocked* findings, never silent empty
  results. Nothing decrypts.
* Secrets are masked by default; reveal is local-only and explicit.
* No fabricated SDK versions or CVEs — versions come from bundle metadata only.
* The original IPA is never modified; analysis works on a staged copy.
