You are the Technical Writer agent for the Rootstock project.

## Context

Read: README.md, ROADMAP.md §Phase 6.2, docs/paper/target-venues.md,
the complete repository state after Phase 6.1

## Task: Phase 6.2 — Erst-Veröffentlichung

Prepare all release materials and announcement content for Rootstock's public debut.

### Step 1: Release Checklist
Create `docs/release/v0.1.0-checklist.md`:
- [ ] All Phase 5 acceptance criteria met
- [ ] All Phase 6.1 acceptance criteria met
- [ ] README Quick Start tested on a clean machine
- [ ] Release binary tested on macOS 14 AND macOS 15
- [ ] No `FIXME` or `TODO` in public-facing code
- [ ] Git history clean (no force-pushes pending)
- [ ] Repository description set on GitHub
- [ ] Topics/tags set: `macos`, `security`, `attack-path`, `tcc`, `graph`, `neo4j`, `bloodhound`, `red-team`, `blue-team`

### Step 2: GitHub Release
Create `docs/release/v0.1.0-release-notes.md`:
```markdown
# Rootstock v0.1.0 — Initial Release

**Graph-based attack path discovery for macOS security boundaries**

## What is Rootstock?

Rootstock maps the invisible trust relationships on macOS endpoints — TCC grants,
entitlements, code signing, XPC services, and Keychain ACLs — and visualizes them
as an exploitable graph. Think BloodHound for macOS-native security boundaries.

## Highlights

- **Swift-native collector** scans a macOS endpoint in seconds
- **Neo4j graph model** with 8 node types and 10+ relationship types
- **20+ pre-built Cypher queries** for Red Team, Blue Team, and Forensic use cases
- **Automated report generation** with Mermaid attack path diagrams
- Supports macOS 14 Sonoma and macOS 15 Sequoia

## Quick Start

\`\`\`bash
# 1. Scan your Mac
./rootstock-collector --output scan.json

# 2. Start Neo4j and import
docker compose -f graph/docker-compose.yml up -d
python3 graph/setup.py
python3 graph/import.py --input scan.json
python3 graph/infer.py

# 3. Explore attack paths
open http://localhost:7474
# Run: :play rootstock
\`\`\`

## Downloads

- `rootstock-collector-v0.1.0-universal.tar.gz` — Universal Binary (Intel + Apple Silicon)
- SHA256: [checksum]

## What's Next

- BloodHound OpenGraph integration
- Live process analysis
- Multi-host graph merging
- Conference presentation at [target venue]

## Acknowledgments

[University], [Advisor], and the macOS security research community.
```

### Step 3: Announcement Blog Post
Create `docs/release/blog-post.md`:
- Title: "Introducing Rootstock: BloodHound for macOS Security Boundaries"
- Structure:
  1. The problem (macOS security boundaries are complex and invisible)
  2. What Rootstock does (collect → graph → query → discover)
  3. Example finding (one real attack path with diagram)
  4. How to try it (Quick Start)
  5. Call for contributions
  6. Link to GitHub, paper (if applicable)
- Length: ~800-1200 words
- Tone: professional but accessible, for the infosec community
- Suitable for: university blog, personal blog, or GitHub Pages

### Step 4: Social Media Announcements
Create `docs/release/announcements.md`:
- **Twitter/X thread (5 tweets):**
  1. "Introducing Rootstock 🌳 — graph-based attack path discovery for macOS. Think BloodHound, but for TCC, entitlements, and code signing. [link]"
  2. "macOS security boundaries create complex trust relationships. Rootstock maps them as a graph and finds attack paths automatically."
  3. "Example: Found an Electron app with Full Disk Access that's injectable via ELECTRON_RUN_AS_NODE. One hop to complete TCC takeover. 🎯"
  4. "20+ pre-built Cypher queries for red team (attack paths), blue team (audits), and forensics. Open source, GPLv3."
  5. "Built as a research project at [University]. Looking for contributors and feedback. Try it: [link] Paper coming soon."

- **Reddit post (r/netsec):**
  - Title: "Rootstock — A BloodHound-inspired attack path mapper for macOS (TCC, entitlements, code signing)"
  - Body: 3-paragraph summary + link + "AMA in comments"

- **Community-specific posts:**
  - SpecterOps/BloodHound Discord: focus on OpenGraph integration potential
  - Objective-See Slack: focus on macOS-specific research contributions
  - r/macsysadmin: focus on blue team / audit use case

### Step 5: Demo Video Script
Create `docs/release/demo-video-script.md`:
- 5-minute screencast script:
  - 0:00-0:30 — "What is Rootstock?" (title card + one-sentence pitch)
  - 0:30-1:30 — Run the collector, show JSON output briefly
  - 1:30-2:30 — Import into Neo4j, show graph in browser
  - 2:30-4:00 — Run 3 key queries, show attack paths found
  - 4:00-4:30 — Generate a report, show the Mermaid diagram
  - 4:30-5:00 — "Get involved" (GitHub link, call for contributions)
- Terminal commands for each step (copy-pasteable)
- Narration notes for each segment

### Step 6: Release Execution
When everything is prepared:
- [ ] `git tag v0.1.0`
- [ ] `git push origin v0.1.0` (triggers release workflow if CI is set up)
- [ ] Upload binary to GitHub Release if not automated
- [ ] Copy release notes to GitHub Release page
- [ ] Publish blog post
- [ ] Post announcements (Twitter, Reddit, Discord/Slack)
- [ ] Record and upload demo video (optional for v0.1.0)

## Acceptance Criteria

- [ ] Release notes (v0.1.0-release-notes.md) are complete and accurate
- [ ] Blog post draft is complete (~800-1200 words)
- [ ] Twitter thread, Reddit post, and community-specific announcements drafted
- [ ] Demo video script covers the full workflow in 5 minutes
- [ ] Release checklist exists and all items can be verified
- [ ] GitHub Release page content is ready to copy-paste
- [ ] All links in announcements point to the actual repository
- [ ] No placeholder text remaining (except [University] / [Author] names)
- [ ] Tone is professional, accessible, and appropriate for the security community

## If Stuck

After 10 iterations:
- If blog post is hard to write: focus on the announcement tweets and release notes only.
  Blog can come later.
- If demo video script is premature: skip it for v0.1.0, add in v0.2.0
- If you don't know the exact findings to highlight: use fixture data to create representative examples
- Priority: release notes > announcements > blog post > demo video script

When ALL acceptance criteria are met, output:
<promise>PHASE_6_2_COMPLETE</promise>
