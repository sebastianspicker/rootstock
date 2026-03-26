You are the Collector Engineer agent for the Rootstock project.

## Context

Read these files first:
- CLAUDE.md (conventions)
- ARCHITECTURE.md §Collector, §Application node properties
- docs/research/entitlements-reference.md (security-critical entitlements, classification)
- collector/Sources/Models/ (existing Application, EntitlementInfo structs)

## Task: Phase 1.3 — App Discovery & Entitlement Scanner

Implement the module that discovers all installed apps and extracts their entitlements.

### Step 1: App Discovery
Create `collector/Sources/Entitlements/AppDiscovery.swift`:
- Scan these directories for `.app` bundles (recursively one level into subdirectories):
  - `/Applications/`
  - `~/Applications/`
  - `/System/Applications/` (skip if not readable)
  - `/System/Applications/Utilities/`
- For each .app bundle found:
  - Read `Contents/Info.plist` → extract CFBundleIdentifier, CFBundleShortVersionString, CFBundleName
  - Resolve the main executable path via `Contents/MacOS/<CFBundleExecutable>`
  - Skip bundles without a valid Info.plist or executable
- Return list of `DiscoveredApp` structs: (name, bundle_id, path, version, executable_path)
- Log count: "Discovered N applications"

### Step 2: Entitlement Extraction
Create `collector/Sources/Entitlements/EntitlementExtractor.swift`:
- For a given executable path, extract entitlements using Security.framework:
  ```swift
  import Security
  // SecStaticCodeCreateWithPath → SecCodeCopySigningInformation
  // Extract kSecCodeInfoEntitlementsDict
  ```
- If Security.framework API fails, fall back to parsing `codesign` CLI output:
  ```swift
  // Process: codesign -d --entitlements :- --xml <path>
  // Parse resulting plist XML
  ```
- Return `[String: Any]` dictionary of entitlements (or empty dict on failure)

### Step 3: Entitlement Classification
Create `collector/Sources/Entitlements/EntitlementClassifier.swift`:
- Take raw entitlement dict → produce `[EntitlementInfo]` array
- Classification logic (from docs/research/entitlements-reference.md):
  - `com.apple.private.tcc.*` → category: `.tcc`, is_private: true
  - `com.apple.security.cs.allow-dyld-environment-variables` → category: `.injection`
  - `com.apple.security.cs.disable-library-validation` → category: `.injection`
  - `com.apple.security.cs.allow-unsigned-executable-memory` → category: `.injection`
  - `com.apple.security.get-task-allow` → category: `.privilege`
  - `com.apple.security.cs.debugger` → category: `.privilege`
  - `com.apple.rootless.*` → category: `.privilege`, is_private: true
  - `com.apple.security.app-sandbox` → category: `.sandbox`
  - `com.apple.security.network.*` → category: `.network`
  - `keychain-access-groups` → category: `.keychain`
  - Everything else → category: `.other`
- `is_private` = name contains "com.apple.private."
- `isSecurityCritical` = category is .tcc, .injection, or .privilege

### Step 4: Electron Detection
In `AppDiscovery.swift` or a separate utility:
- For each .app bundle, check if `Contents/Frameworks/Electron Framework.framework` exists
- Set `is_electron: true` on the Application model if found
- Also check for `Contents/Frameworks/Squirrel.framework` as secondary indicator

### Step 5: EntitlementDataSource
Create `collector/Sources/Entitlements/EntitlementDataSource.swift`:
- Conforms to `DataSource` protocol
- `requiresElevation`: false
- `collect()` does:
  1. Run AppDiscovery → list of discovered apps
  2. For each app: extract entitlements, classify them
  3. Detect Electron status
  4. Build `Application` objects with populated entitlements
  5. Catch per-app failures → add to errors, continue with next app
  6. Return DataSourceResult

### Step 6: Testing
- Create a test fixture: a minimal self-signed .app bundle with known entitlements
  (use `codesign --sign -` with an entitlements plist)
- Test: discover apps in a fixture directory → correct count and bundle IDs
- Test: extract entitlements from fixture app → correct entitlement names
- Test: classify entitlements → correct categories and is_private flags
- Test: invalid/corrupted app bundle → graceful skip with error

## Acceptance Criteria

- [ ] `swift build` succeeds with zero warnings
- [ ] `EntitlementDataSource` conforms to `DataSource` protocol
- [ ] Running collector produces JSON with `applications` array
- [ ] Each application has: name, bundle_id, path, version, entitlements array
- [ ] Each entitlement has: name, is_private, category, is_security_critical
- [ ] Electron apps are correctly detected (is_electron: true)
- [ ] At least `/Applications/` and `/System/Applications/` are scanned
- [ ] Apps that fail entitlement extraction are skipped with error, not crash
- [ ] On a real Mac, the collector finds >20 applications with entitlements
- [ ] Security.framework API is used as primary extraction method
- [ ] CLI fallback to `codesign` works when API fails

## If Stuck

After 15 iterations:
- If Security.framework APIs are hard to use from Swift: use the `codesign` CLI
  fallback as the primary method for the MVP. Document in tech-debt-tracker.md.
- If system apps under SSV refuse to yield entitlements: skip them with a warning,
  focus on /Applications/ (third-party apps are more interesting for attack paths anyway)
- If building a fixture .app for tests is complex: test with real system apps
  (e.g., Terminal.app) whose entitlements are known and stable

When ALL acceptance criteria are met, output:
<promise>PHASE_1_3_COMPLETE</promise>
