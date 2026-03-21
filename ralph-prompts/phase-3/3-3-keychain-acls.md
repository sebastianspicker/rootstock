You are the Collector Engineer agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §Keychain_Item node, §CAN_READ_KEYCHAIN edge,
docs/references/macos-security-llm-reference.md §Keychain, CLAUDE.md §Security Principles

CRITICAL: This module collects METADATA ONLY — never extract passwords, keys, or secret values.

## Task: Phase 3.3 — Keychain ACL Metadata

Extract Keychain item metadata and access control lists to model trust relationships.

### Steps

1. **Keychain Item Enumeration** — Create `collector/Sources/Keychain/KeychainScanner.swift`:
   - Use Security.framework: `SecItemCopyMatching` with `kSecReturnAttributes: true`
     and `kSecReturnData: false` (NEVER set kSecReturnData to true)
   - Query for: kSecClassGenericPassword, kSecClassInternetPassword, kSecClassCertificate, kSecClassKey
   - Extract per item: kSecAttrLabel, kSecAttrService, kSecAttrAccount, kSecAttrAccessGroup, kSecAttrType
   - Do NOT extract: kSecValueData, kSecValueRef (these contain secrets)

2. **ACL Extraction** — For each item, extract the access control list:
   - `SecKeychainItemCopyAccess` → `SecAccessCopyACLList`
   - For each ACL entry: get the list of trusted applications (SecTrustedApplicationCopyData)
   - Map trusted app paths → bundle IDs where possible
   - Determine: which apps can read this item without prompting the user?

3. **Keychain_Item Model** — Codable struct: label, kind (generic_password/internet_password/
   certificate/key), service, access_group, trusted_apps: [String] (bundle IDs)
   NO secret values anywhere.

4. **KeychainDataSource** — Conforms to DataSource. requiresElevation: true (for system keychain).
   User login keychain accessible without elevation IF unlocked.

5. **Graph Edges** — CAN_READ_KEYCHAIN: Application → Keychain_Item (where app is in trusted_apps)

6. **Caution** — Some Keychain APIs trigger user prompts. Use only metadata APIs.
   If a prompt would appear, skip that item and log an error.

## Acceptance Criteria

- [ ] JSON output contains `keychain_acls` array with metadata only
- [ ] NO passwords, keys, or secret data appear anywhere in the output
- [ ] Each Keychain item has: label, kind, service, access_group, trusted_apps
- [ ] User login keychain items are enumerated without user prompts
- [ ] System keychain: graceful skip if not accessible
- [ ] Graph import creates Keychain_Item nodes and CAN_READ_KEYCHAIN edges
- [ ] At least some apps have CAN_READ_KEYCHAIN edges on a real Mac

## If Stuck

After 15 iterations:
- Keychain APIs are notoriously tricky from Swift. If SecItemCopyMatching doesn't return
  ACL data, try the older SecKeychainItem APIs via Objective-C bridging.
- If user prompts appear: immediately abort that code path and skip the item.
  User prompts are unacceptable for an automated scanner.
- Minimal viable: even just listing items with their access_groups (without full ACL details)
  is valuable. Ship that and iterate on ACL extraction later.

When ALL acceptance criteria are met, output:
<promise>PHASE_3_3_COMPLETE</promise>
