You are a senior security researcher performing a systematic review of the Rootstock inference engine — the modules that discover attack paths by analyzing the property graph and creating inferred relationships between nodes.

## Context

Read: CLAUDE.md, ARCHITECTURE.md, docs/QUALITY.md,
graph/infer.py (orchestrator),
graph/infer_injection.py, graph/infer_accessibility.py, graph/infer_esf.py,
graph/infer_file_acl.py, graph/infer_finder_fda.py, graph/infer_group_capabilities.py,
graph/infer_kerberos.py, graph/infer_keychain_groups.py, graph/infer_mdm_overgrant.py,
graph/infer_password.py, graph/infer_shell_hooks.py,
graph/tier_classification.py, graph/mark_owned.py, graph/clear_owned.py,
graph/constants.py, graph/models.py,
graph/tests/ (all inference-related tests)

## Priority Definitions

- **P0 — Critical:** Inference creates logically impossible attack paths, produces edges that could mislead a security assessment, or has a Cypher injection vulnerability
- **P1 — High:** Missing attack vector that should be inferred, incorrect edge direction (implies wrong attacker/target relationship), wrong properties on inferred edges, inference depends on node types that import doesn't create
- **P2 — Medium:** Overly broad pattern matching creating excessive false positives, performance issues on large graphs, missing idempotency
- **P3 — Low:** Style issues, missing docstrings, hardcoded values that should be constants

## Task: Review Phase C — Inference Engine

Perform an iterative, priority-ordered review of every inference module. For each module, validate both the Cypher logic and the security reasoning behind the inferred relationships.

### C.1 Per-Module Inference Review

For EACH inference module (`infer_*.py`):
- [ ] **Cypher correctness:** Does the MERGE/CREATE statement produce valid edges? Are MATCH patterns correct?
- [ ] **Edge direction:** Does `(:Source)-[:RELATIONSHIP]->(:Target)` correctly model "Source can attack/access Target"?
- [ ] **Properties:** Are edge properties (description, risk level, method) accurate and helpful?
- [ ] **Node type references:** Does the Cypher reference node labels and properties that actually exist in the imported graph?
- [ ] **False positive risk:** Is the matching pattern too broad? Could it create edges for scenarios that aren't actually exploitable?
- [ ] **False negative risk:** Are there known attack variants this module should catch but doesn't?
- [ ] **Idempotency:** Running the inference twice produces the same graph (no duplicate edges)?
- [ ] **Error handling:** Does the module handle missing node types gracefully (e.g., if no FileACL nodes exist)?

### C.2 Inference Orchestrator

Review `graph/infer.py`:
- [ ] Does it call ALL inference modules? Cross-reference with the list of `infer_*.py` files
- [ ] Is the execution order correct? (Some inferences may depend on edges created by others)
- [ ] Does it report what was inferred (edge counts per module)?
- [ ] Does it handle individual module failures without aborting?
- [ ] Are there any circular dependencies between inference modules?

### C.3 Attack Path Correctness

For 5 representative attack paths, trace the logic end-to-end:
1. **Dylib injection → FDA:** App injectable via DYLD_INSERT → injects into app with Full Disk Access
2. **Electron exploitation:** Electron app with TCC → parent process inherits permissions
3. **Accessibility abuse:** App with Accessibility → can control other apps
4. **Kerberos ticket theft:** Injectable app with Kerberos artifacts → credential theft
5. **Shell hook injection:** Writable shell config → code execution in user context

For each path:
- [ ] Are all necessary edges created by inference?
- [ ] Does the chain make security sense (each hop is a real attack technique)?
- [ ] Could a real attacker actually execute this path?

### C.4 Tier Classification

Review `graph/tier_classification.py`:
- [ ] Are tier boundaries correct (Tier 0 = most critical assets, Tier 3 = least)?
- [ ] Does classification align with macOS security significance?
- [ ] Is classification deterministic (same input → same tiers)?
- [ ] Are there node types that should be classified but aren't?
- [ ] Does reclassification (running twice) produce stable results?

### C.5 Owned Node Management

Review `graph/mark_owned.py` and `graph/clear_owned.py`:
- [ ] Does marking a node as owned correctly propagate through relationships?
- [ ] Does clearing owned state remove ALL owned markers (no orphaned state)?
- [ ] Is the owned/not-owned state correctly used by queries and reports?
- [ ] Are there race conditions if mark/clear are called concurrently?

### C.6 Inference Tests

Review all inference-related tests:
- [ ] Is there at least one test per inference module?
- [ ] Do tests verify edge creation (not just that the function runs without error)?
- [ ] Do tests verify edge direction and properties?
- [ ] Do tests cover the "no match" case (inference runs on graph without matching patterns → no edges created)?
- [ ] Run the tests — do they all pass?

## Output

For each iteration, state:
1. What you reviewed
2. Issues found (with priority and security impact)
3. Fixes applied
4. What remains

After all issues are resolved, produce a summary:

```
## Review C Summary — Inference Engine
- Modules reviewed: [count] / [total]
- P0 issues found/fixed: [N]
- P1 issues found/fixed: [N]
- P2 issues found/fixed: [N]
- P3 issues deferred: [N]
- Attack paths validated: 5/5
- Inference modules with tests: [N] / [total]
- Tier classification: [deterministic/non-deterministic]
```

## Acceptance Criteria

- [ ] All inference tests pass
- [ ] No module creates logically incorrect edges (wrong direction, impossible attack)
- [ ] Every inference module references node types/properties that exist in the imported graph
- [ ] Tier classification produces deterministic results
- [ ] mark_owned / clear_owned leave no orphaned state
- [ ] No P0 or P1 issues remain open
- [ ] P2/P3 issues documented in tech-debt-tracker.md

## If Stuck

After 20 iterations:
- If a false-positive issue requires deeper macOS security research: document the uncertainty in a code comment, add a TODO, and move on
- If an inference module depends on node types not yet in fixture_minimal.json: add the minimal fixture data needed
- If attack path validation reveals a design-level issue: document in tech-debt-tracker.md for the final consistency loop
- Priority: edge direction correctness > false positive reduction > test coverage > style

When ALL acceptance criteria are met, output:
<promise>REVIEW_C_COMPLETE</promise>
