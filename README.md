# IPA Inspector

A SwiftUI iOS app that inspects iOS app archives (`.ipa`) entirely on-device, plus a
portable Swift package (`IPAKit`) holding all of the analysis logic.

## What it does

- **IPA analysis** — safe ZIP extraction (path traversal, symlink, zip-bomb and size
  policy), Mach-O parsing (thin + FAT, load commands, segments, UUID, entitlements
  from the code signature), Info.plist / provisioning profile / privacy manifest
  inspection, SDK fingerprinting, URL and host collection, and redacted
  credential-pattern scanning. Encrypted (FairPlay) binaries are reported as
  *blocked*, never guessed at.
- **App Store lookup** — public listing metadata for a store link or app ID; it
  never fetches a binary.
- Every finding carries a source path, an evidence status and a note explaining
  what it does and does not prove. Reports export as JSON.

## Layout

```
Sources/IPAKit/    Analysis logic (Swift package, tested on Linux and iOS)
App/               SwiftUI app layer (iOS 17+)
Tests/IPAKitTests/ Unit + end-to-end tests over synthetic archives
project.yml        XcodeGen spec for the iOS application target
```

## Building the app (macOS)

```bash
brew install xcodegen
xcodegen generate
xcodebuild -project IPAInspector.xcodeproj -scheme IPAInspector \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath build \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=""
```

The unsigned `.app` is then zipped into `Payload/…` to form an installable IPA.
GitHub Actions does exactly this on every push to `main` and publishes the result
as a GitHub Release asset (`IPAInspector-unsigned.ipa`).

## Running the tests

```bash
swift test
```

The logic tests run on macOS and Linux without any Apple-specific framework.

## Honest limitations

Static analysis cannot prove completeness. URLs assembled at runtime, secrets
behind encryption, and SDK behaviour are out of reach; the report marks those
limits instead of papering over them. Nothing here retrieves an IPA from an App
Store link, and nothing decrypts FairPlay.
