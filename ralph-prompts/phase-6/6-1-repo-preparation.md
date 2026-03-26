You are the Planner agent for the Rootstock project.

## Context

Read: CLAUDE.md, README.md, docs/QUALITY.md §Security Quality,
all existing source code and documentation

## Task: Phase 6.1 — Repository-Aufbereitung

Prepare the repository for public release — clean, professional, and safe to publish.

### Step 1: Sensitive Data Audit
Perform a thorough audit of the entire repository:
- [ ] `grep -r "password\|secret\|token\|key\|credential" --include="*.swift" --include="*.py" --include="*.json" --include="*.md"` → review every match
- [ ] Verify no real scan outputs are committed (only fixtures with synthetic data)
- [ ] Verify no real hostnames, usernames, or IP addresses in documentation
- [ ] Verify no hardcoded paths containing real user home directories
- [ ] Check git history: `git log --all --oneline --diff-filter=D` for accidentally deleted sensitive files
- [ ] If any sensitive data found in history: document the need for `git filter-branch` or BFG before going public
- Create `scripts/audit-secrets.sh` that automates these checks

### Step 2: License & Legal
Create/verify these files:
- `LICENSE` — full GPLv3 text
- `CONTRIBUTING.md`:
  - How to report security vulnerabilities (dedicated email/process)
  - How to contribute code (fork, branch, PR, code review)
  - Coding standards (link to CLAUDE.md conventions)
  - DCO (Developer Certificate of Origin) sign-off requirement
  - How to add a new data source module
  - How to add a new Cypher query
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1 or similar
- `SECURITY.md` — security vulnerability reporting process
  - Do NOT open public issues for security vulnerabilities
  - Email: [security contact]
  - Expected response time, disclosure timeline

### Step 3: GitHub Issue Templates
Create `.github/ISSUE_TEMPLATE/`:
- `bug_report.yml`:
  - macOS version, collector version, steps to reproduce, expected vs actual behavior
  - Option to attach (redacted) scan JSON
- `feature_request.yml`:
  - Use case description, proposed solution, alternatives considered
- `new_data_source.yml`:
  - What data source to add, where the data lives on macOS, what attack paths it enables
  - API/command to access the data, elevation requirements

### Step 4: GitHub Actions CI
Create/update `.github/workflows/`:
- `build.yml` — on push/PR:
  - macOS runner: `swift build`, `swift test`
  - Ubuntu runner: `pip install`, `ruff check`, `pytest` (graph tests without Neo4j)
  - Fail on warnings (Swift), fail on lint violations (Python)
- `release.yml` — on tag push (v*):
  - Build Universal Binary: `swift build -c release --arch arm64 --arch x86_64`
  - Create GitHub Release with binary attached
  - Generate checksums (SHA256)
  - Attach example scan schema and query library

### Step 5: Release Binary
Create `scripts/build-release.sh`:
- Build universal binary (Intel + Apple Silicon):
  ```bash
  swift build -c release --arch arm64
  swift build -c release --arch x86_64
  lipo -create .build/arm64-apple-macosx/release/rootstock-collector \
       .build/x86_64-apple-macosx/release/rootstock-collector \
       -output rootstock-collector-universal
  ```
- Strip debug symbols: `strip rootstock-collector-universal`
- Create .tar.gz archive with binary + README + LICENSE
- Generate SHA256 checksum
- Test: verify binary runs on both architectures

### Step 6: Repository Cleanup
- [ ] Remove any TODO/FIXME comments that reference internal details
- [ ] Ensure .gitignore covers all build artifacts, IDE files, scan outputs
- [ ] Remove harness engineering docs that are internal-only (or move to separate branch)
  Decision: keep ralph-prompts/ and docs/exec-plans/? They could be valuable for contributors.
  Recommendation: keep them — transparency about the development process is a plus.
- [ ] Verify all links in README work (no broken relative links)
- [ ] Verify all file references in documentation point to existing files
- [ ] Run a final `swift build -c release` and `pytest` to confirm everything works

## Acceptance Criteria

- [ ] Secret audit script exists and passes with no findings
- [ ] No real user data, hostnames, or credentials anywhere in the repository
- [ ] LICENSE (GPLv3), CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md all exist
- [ ] GitHub Issue Templates for bug report, feature request, new data source
- [ ] CI workflow: build + test on macOS and Ubuntu
- [ ] Release workflow: builds universal binary on tag push
- [ ] `scripts/build-release.sh` produces a working universal binary
- [ ] .gitignore is comprehensive
- [ ] All documentation links are valid
- [ ] Final build and test pass clean

## If Stuck

After 10 iterations:
- If universal binary (lipo) fails: ship arm64-only for v0.1.0, add Intel in v0.1.1
- If GitHub Actions macOS runner has Swift issues: use `xcodebuild` as fallback
- If release workflow is complex: skip automated releases, do manual GitHub Release
- Priority: secret audit > license/legal > CI > release automation

When ALL acceptance criteria are met, output:
<promise>PHASE_6_1_COMPLETE</promise>
