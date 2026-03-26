You are the Collector Engineer agent for the Rootstock project.

## Context

Read: ARCHITECTURE.md §MDM_Profile node, §CONFIGURES edge

## Task: Phase 3.4 — MDM Profile Analysis

Extract installed MDM configuration profiles and identify TCC-relevant policies.

### Steps

1. **Profile Extraction** — Create `collector/Sources/MDM/MDMProfileScanner.swift`:
   - Run `profiles show -all -output stdout-xml` and parse the XML plist output
   - Alternative: `profiles -C -o stdout` for a simpler listing
   - For each profile: extract ProfileIdentifier, ProfileDisplayName, ProfileOrganization,
     ProfileInstallDate, PayloadContent array
   - Handle: no profiles installed → return empty, command not available → graceful error

2. **TCC Policy Detection** — In PayloadContent, look for:
   - PayloadType = "com.apple.TCC.configuration-profile-policy" (Privacy Preferences Policy Control)
   - These contain Services dict with TCC service names and their forced allow/deny status
   - Extract: which bundle IDs are granted which TCC services via MDM

3. **MDM_Profile Model** — Codable struct: identifier, display_name, organization,
   install_date, tcc_policies: [{service, client_bundle_id, allowed}]

4. **MDMDataSource** — Conforms to DataSource. requiresElevation: false for listing,
   but some details may need admin. Graceful degradation.

5. **Graph Edges** — CONFIGURES: MDM_Profile → TCC_Permission (for MDM-managed grants)
   Also update HAS_TCC_GRANT edges with `{managed: true}` when the grant comes from MDM

6. **Query** — `graph/queries/09-mdm-managed-tcc.cypher`:
   Show all TCC permissions managed by MDM vs. user-granted — relevant for enterprise audits

## Acceptance Criteria

- [ ] JSON output contains `mdm_profiles` array (empty on non-managed Macs)
- [ ] On MDM-managed Macs: profiles with TCC policies are correctly parsed
- [ ] Graph import creates MDM_Profile nodes and CONFIGURES edges
- [ ] MDM-managed TCC grants are distinguishable from user-granted ones in the graph
- [ ] Graceful handling: unmanaged Macs produce empty array, no errors
- [ ] `profiles` command failure is caught (not all Macs have it available the same way)

## If Stuck

After 10 iterations:
- If testing on a non-MDM Mac: create the module structure and test with synthetic
  profile XML. Mark real-Mac testing as a todo.
- If `profiles` command output format differs: parse loosely and extract what's available
- This is the least critical Phase 3 module — ship minimal viable and move on

When ALL acceptance criteria are met, output:
<promise>PHASE_3_4_COMPLETE</promise>
