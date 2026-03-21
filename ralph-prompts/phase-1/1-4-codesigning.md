You are the Collector Engineer agent for the Rootstock project.

## Context

Read these files first:
- ARCHITECTURE.md §Application node properties (hardened_runtime, library_validation, team_id, signed)
- docs/research/entitlements-reference.md §Injection-Enabling Entitlements
- collector/Sources/Entitlements/ (existing AppDiscovery and Application models from 1.3)

## Task: Phase 1.4 — Code Signing Analysis

Add code signing metadata to every discovered application — this determines which apps are injectable.

### Step 1: Code Signing Extractor
Create `collector/Sources/CodeSigning/CodeSigningAnalyzer.swift`:
- For a given app path, use Security.framework:
  ```swift
  import Security

  func analyze(appPath: String) -> CodeSigningInfo {
      var staticCode: SecStaticCode?
      let url = URL(fileURLWithPath: appPath) as CFURL
      SecStaticCodeCreateWithPath(url, [], &staticCode)

      var info: CFDictionary?
      SecCodeCopySigningInformation(staticCode!, [.signingInformation], &info)

      // Extract from info dict:
      // kSecCodeInfoTeamIdentifier → team_id
      // kSecCodeInfoFlags → check for kSecCodeSignatureRuntime (hardened runtime)
      // Check for library validation in flags
      // kSecCodeInfoIdentifier → signing identifier
  }
  ```
- Return `CodeSigningInfo` struct: team_id, hardened_runtime, library_validation, signed, signing_identifier

### Step 2: Injection Vulnerability Assessment
Create `collector/Sources/CodeSigning/InjectionAssessment.swift`:
- For each app, determine if it is injectable based on:
  1. `hardened_runtime == false` → injectable via DYLD_INSERT_LIBRARIES
  2. `hardened_runtime == true` BUT has `allow-dyld-environment-variables` entitlement → injectable via DYLD_INSERT_LIBRARIES
  3. `library_validation == false` → injectable via unsigned dylib loading
  4. `is_electron == true` → injectable via ELECTRON_RUN_AS_NODE environment variable
- Return `[InjectionMethod]` enum array per app:
  ```swift
  enum InjectionMethod: String, Codable {
      case dyldInsert = "dyld_insert"
      case dyldInsertViaEntitlement = "dyld_insert_via_entitlement"
      case missingLibraryValidation = "missing_library_validation"
      case electronEnvVar = "electron_env_var"
  }
  ```

### Step 3: Merge into Application Model
- Extend the `Application` struct (or create it if needed) to include:
  - `team_id: String?`
  - `hardened_runtime: Bool`
  - `library_validation: Bool`
  - `signed: Bool`
  - `is_system: Bool` (path starts with /System/ or /usr/)
  - `injection_methods: [InjectionMethod]` (computed from assessment)
- The EntitlementDataSource from Phase 1.3 should now also populate these fields

### Step 4: CodeSigningDataSource
Create `collector/Sources/CodeSigning/CodeSigningDataSource.swift`:
- This is NOT a standalone DataSource — instead, it enriches Application objects
  produced by EntitlementDataSource
- Provide a function: `func enrich(applications: inout [Application])`
- For each application: run CodeSigningAnalyzer, run InjectionAssessment, update properties
- Handle failures per-app: if codesign analysis fails, set signed=false and log error

### Step 5: Testing
- Test: Known hardened app (e.g., Safari.app) → hardened_runtime: true, library_validation: true
- Test: Known unsigned/ad-hoc binary → signed: false
- Test: Injection assessment logic with mocked CodeSigningInfo → correct methods
- Test: Electron app (e.g., VS Code, Slack) → is_electron: true, injection_methods contains electron_env_var

## Acceptance Criteria

- [ ] `swift build` succeeds with zero warnings
- [ ] Every Application in the JSON output has: team_id, hardened_runtime, library_validation, signed
- [ ] `injection_methods` array is populated for each app (empty array if not injectable)
- [ ] System apps (under /System/) have `is_system: true`
- [ ] On a real Mac, at least some apps should have `injection_methods` entries
- [ ] Electron apps show `electron_env_var` in their injection_methods
- [ ] Apps where code signing analysis fails get `signed: false` and an error entry
- [ ] Security.framework is used (not just CLI parsing)

## If Stuck

After 12 iterations:
- If `SecCodeCopySigningInformation` is hard to call from Swift due to CF bridging:
  fall back to parsing `codesign -dv --verbose=4 <path>` output (look for "runtime" in flags)
- If hardened runtime flag detection is unreliable: use the presence/absence of the
  `com.apple.security.cs.allow-dyld-environment-variables` entitlement as a secondary signal
- Document any limitations in tech-debt-tracker.md

When ALL acceptance criteria are met, output:
<promise>PHASE_1_4_COMPLETE</promise>
