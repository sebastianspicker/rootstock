# BloodHound → macOS Feature Comparison

> For each BloodHound feature: what is the macOS analog, and does Rootstock implement it?
>
> Last updated: 2026-03-19

---

## 1. Node Types

| BloodHound Node | macOS Analog | Rootstock Status |
|---|---|---|
| **User** | macOS local/network user (`dscl . -list /Users`) | ✅ `User` node — name, uid, is_admin, home, type |
| **Group** | macOS local groups (`dscl . -list /Groups`) | ❌ Not modeled — groups not collected |
| **Computer** | The Mac itself (single-host model) | ⚠️ Implicit — each scan is one host; `hostname` in ScanResult |
| **Domain** | N/A — macOS has no AD domain concept natively | ❌ N/A (single-host tool) |
| **OU** | N/A — no native OU concept | ❌ N/A |
| **GPO** | MDM Configuration Profiles (Jamf, Mosyle, Kandji) | ✅ `MDM_Profile` node — identifier, display_name, organization |
| **Container** | App Bundles (`.app` directories) | ✅ `Application` node — bundle_id, path, version |
| **CertTemplate** | Code Signing Certificates / Provisioning Profiles | ⚠️ Partial — `team_id` and `signed` tracked, but no cert template modeling |
| **EnterpriseCA** | Apple Root CA / Developer ID CA | ❌ Not modeled |
| **RootCA** | Apple Root Certificate Authority | ❌ Not modeled |
| **ADLocalGroup** | macOS local groups (admin, staff, wheel) | ❌ Not modeled |
| **AZApp / AZServicePrincipal** | macOS Applications / Background Services | ✅ `Application` + `XPC_Service` + `LaunchItem` |
| **AZKeyVault** | macOS Keychain | ✅ `Keychain_Item` node — label, kind, service, access_group, trusted_apps |
| **AZRole** | TCC Permission (privacy grant acting as a role) | ✅ `TCC_Permission` node — service, display_name |
| **IssuancePolicy** | Entitlement (code-signing privilege) | ✅ `Entitlement` node — name, is_private, category, is_security_critical |

### macOS-Specific Nodes (no BloodHound equivalent)

| Rootstock Node | macOS Concept | BloodHound Equivalent |
|---|---|---|
| `TCC_Permission` | Privacy grant (FDA, Camera, Mic, etc.) | No direct equivalent — closest is AZRole |
| `Entitlement` | Code-signing privilege declaration | No direct equivalent — closest is CertTemplate permissions |
| `XPC_Service` | Mach-port IPC service (launchd-managed) | No direct equivalent — closest is Computer services |
| `LaunchItem` | Persistence mechanism (daemon/agent/cron/login item) | Partially — scheduled tasks via TaskHound, but not launchd-native |

---

## 2. Edge / Relationship Types

### Identity & Membership

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **MemberOf** | User → Group membership (`dscl . -read /Groups/<name> GroupMembership`) | ❌ Not modeled — no group collection |
| **AdminTo** | User in `admin` group → full local admin | ❌ Not modeled — `is_admin` on User node but no AdminTo edge |
| **HasSession** | Active login sessions (Console, SSH, screen sharing) | ❌ Not modeled — no session enumeration |
| **Contains** | OU/Container hierarchy | N/A |
| **Owns** | File/resource ownership (`stat -f %Su`) | ❌ Not modeled |

### Privilege Escalation

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **GenericAll / GenericWrite / WriteDacl** | File ACL manipulation (`chmod`, `xattr`) | ❌ Not modeled — filesystem ACLs not collected |
| **ForceChangePassword** | `dscl . -passwd` (requires admin) | ❌ Not modeled |
| **DCSync** | N/A — no domain controller concept | ❌ N/A |
| **ReadLAPSPassword** | N/A — no LAPS on macOS | ❌ N/A |
| **ReadGMSAPassword** | N/A | ❌ N/A |
| **AddKeyCredentialLink** (Shadow Credentials) | N/A | ❌ N/A |
| **CanRDP** | Screen Sharing permission (ARD/VNC) | ❌ Not modeled — could check TCC `kTCCServiceScreenCapture` |
| **CanPSRemote** | SSH access (`/etc/ssh/sshd_config`, Remote Login TCC) | ❌ Not modeled |
| **ExecuteDCOM** | Apple Events / AppleScript automation | ✅ `CAN_SEND_APPLE_EVENT` (inferred) |
| **SQLAdmin** | N/A | ❌ N/A |

### Code Signing / Trust

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **TrustedBy / SameForestTrust** | Same Team ID trust (apps signed by same dev team) | ✅ `SIGNED_BY_SAME_TEAM` |
| **GoldenCert** | Stolen Apple Developer Certificate | ❌ Not modeled — would require cert chain analysis |
| N/A | DYLD injection (missing hardened runtime / library validation) | ✅ `CAN_INJECT_INTO` (3 methods) |
| N/A | Electron child process TCC inheritance | ✅ `CHILD_INHERITS_TCC` |

### Lateral Movement

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **HasSession** → credential theft | Keychain ACL → credential access | ✅ `CAN_READ_KEYCHAIN` |
| **AdminTo** → local admin | sudo / admin group membership | ❌ Not modeled as edge |
| N/A | XPC service privilege escalation | ✅ `COMMUNICATES_WITH` + query 15 |
| N/A | Persistence via LaunchDaemon/Agent | ✅ `PERSISTS_VIA` + `RUNS_AS` |
| N/A | MDM-managed TCC policy | ✅ `CONFIGURES` |

### Certificate Services (ADCS)

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **ADCSESC1–ESC13** | N/A — no ADCS on macOS | ❌ N/A |
| **ManageCA / ManageCertificates** | System Keychain cert management | ❌ Not modeled |
| **GoldenCert** | Stolen code-signing identity | ❌ Not modeled |
| **Enroll / EnrollOnBehalfOf** | N/A | ❌ N/A |

### NTLM / Kerberos

| BloodHound Edge | macOS Analog | Rootstock Status |
|---|---|---|
| **CoerceAndRelayNTLM*** | N/A — no NTLM relay on standalone macOS | ❌ N/A |
| **AbuseTGTDelegation** | N/A (Kerberos only in AD-joined Macs) | ❌ N/A |
| **AllowedToDelegate** | N/A | ❌ N/A |
| **Kerberoasting** | Possible on AD-joined Macs (Bifrost) | ❌ N/A — not in scope (standalone macOS) |

---

## 3. Attack Path Categories

| BloodHound Attack Category | macOS Analog | Rootstock Status |
|---|---|---|
| **Kerberoasting** | N/A (AD-joined only → Bifrost) | ❌ Out of scope |
| **AS-REP Roasting** | N/A | ❌ Out of scope |
| **DCSync** | N/A | ❌ Out of scope |
| **LAPS Password Reading** | N/A | ❌ Out of scope |
| **ADCS Certificate Abuse** | N/A (no ADCS on macOS) | ❌ Out of scope |
| **NTLM Relay** | N/A (standalone macOS) | ❌ Out of scope |
| **ACL/DACL Abuse** | File permission / xattr abuse | ❌ Not modeled — **candidate for future** |
| **Lateral Movement (RDP/PSRemote)** | SSH / Screen Sharing / ARD | ❌ Not modeled — **candidate for future** |
| **Golden Ticket** | N/A | ❌ Out of scope |
| **SID History** | N/A | ❌ Out of scope |
| **Shadow Credentials** | N/A | ❌ Out of scope |
| **Constrained/Unconstrained Delegation** | N/A | ❌ Out of scope |
| **GPO Abuse** | MDM Profile Abuse | ⚠️ Partial — MDM profiles collected, but no abuse path modeled |
| **Local Admin Abuse** | sudo / admin group → full control | ❌ Not modeled — **candidate for future** |
| **Session Credential Theft** | Keychain credential access via injection | ✅ Query 13 (keychain-via-injection) |
| N/A | **TCC Grant Abuse** (DYLD inject → inherit FDA) | ✅ Queries 01, 02, 06, 12 |
| N/A | **Electron TCC Inheritance** | ✅ Query 03 |
| N/A | **Apple Event Cascade** | ✅ Queries 05, 11 |
| N/A | **XPC Privilege Escalation** | ✅ Query 15 |
| N/A | **Persistent Root Execution** | ✅ Query 14 |
| N/A | **Stale TCC Grant Reuse** | ✅ Query 19 |
| N/A | **Private Entitlement Abuse** | ✅ Query 04 |
| N/A | **TCC DB Write (Full Takeover)** | ✅ Query 12 |

---

## 4. Data Collection

| BloodHound Collector (SharpHound) | macOS Equivalent | Rootstock Status |
|---|---|---|
| **LDAP queries** (AD objects) | `dscl` / OpenDirectory queries | ❌ Not collected |
| **SMB named pipes** (sessions, local groups) | N/A | ❌ N/A |
| **DCE/RPC** (session enumeration) | N/A | ❌ N/A |
| **WMI / Remote Registry** | N/A (no WMI on macOS) | ❌ N/A |
| **ACL enumeration** (AD DACLs) | File ACLs / extended attributes | ❌ Not collected — **candidate** |
| **Certificate Services** (AD CS) | Code signing certificates | ⚠️ Partial — team_id, signed status |
| **Group membership** | Local groups via `dscl` | ❌ Not collected — **candidate** |
| **User properties** | `dscl . -read /Users/<name>` | ⚠️ Partial — name, uid, is_admin only |
| **DNS resolution** | `dscacheutil -flushcache` / mDNS | ❌ Not collected |
| **Trust relationships** | N/A (no AD trusts) | ❌ N/A |
| N/A | **TCC database** (user + system) | ✅ Full SQLite parsing with PRAGMA detection |
| N/A | **Code signing** (hardened runtime, library validation) | ✅ Security.framework + codesign CLI |
| N/A | **Entitlements** (per-app privilege declarations) | ✅ codesign + SecCodeCopySigningInformation |
| N/A | **XPC services** (launchd plist enumeration) | ✅ All LaunchDaemon/Agent directories |
| N/A | **Keychain ACLs** (metadata, trusted apps) | ✅ SecItemCopyMatching (no secrets) |
| N/A | **Persistence** (daemons, agents, cron, login items, hooks) | ✅ 5 persistence sources |
| N/A | **MDM profiles** (configuration + TCC policies) | ✅ `profiles -C` parsing |

---

## 5. Analysis & Visualization

| BloodHound Feature | macOS Analog | Rootstock Status |
|---|---|---|
| **Interactive graph UI** (Sigma.js) | Neo4j Browser + custom queries | ⚠️ Neo4j Browser only (no custom UI) |
| **Shortest path finding** | Cypher `shortestPath()` | ✅ Query 02 (shortest-path-to-fda) |
| **Pre-built queries** (170+ in library) | Pre-built Cypher library | ✅ 23 queries (11 red, 9 blue, 3 forensic) |
| **Custom Cypher editor** | Neo4j Browser Cypher console | ✅ Via Neo4j Browser |
| **Edge type filtering** | N/A | ❌ Not in CLI; available in Neo4j Browser |
| **Tier Zero / High Value marking** | High-value target scoring | ✅ Query 21 (attack-value-score ranking) |
| **"Owned" node marking** | N/A | ❌ Not implemented |
| **Entity info panel** | N/A | ❌ No custom UI — use Neo4j Browser |
| **Saved queries** | Saved queries file for Neo4j Browser | ✅ `graph/browser/saved-queries.cypher` |
| **Posture tracking** (Enterprise) | N/A | ❌ Not implemented |
| **Attack path management** (Enterprise) | N/A | ❌ Not implemented |
| **Multi-environment** (AD + Azure + GitHub + Okta) | Single-host macOS only | ❌ macOS-only; no multi-platform |
| **REST API** | N/A | ❌ No API (CLI-only) |
| **RBAC / Multi-user** | N/A | ❌ Single-user tool |
| **Data upload / ingestion API** | CLI import (`import.py`) | ✅ CLI-based import |
| **Markdown report generation** | N/A | ✅ `report.py` with Mermaid diagrams |
| **HTML report generation** | N/A | ✅ `report.py --format html` |
| **Graphviz DOT export** | N/A | ✅ `report_graphviz.py` |
| **CSV export** | N/A | ✅ `query_runner.py --format csv` |
| **JSON export** | N/A | ✅ `query_runner.py --format json` |

---

## 6. Feature Gap Analysis — Candidates for Rootstock

### High Value (macOS-native, would add significant analysis capability)

| Feature | macOS Implementation | Effort | Impact |
|---|---|---|---|
| **Local group membership** | `dscl . -read /Groups/admin GroupMembership` → model as MemberOf edges | Medium | Identifies which users are admin — essential for privilege analysis |
| **SSH / Remote Login** | Check `systemsetup -getremotelogin`, TCC `kTCCServiceRemoteLogin` | Low | Identifies remote access vectors |
| **Screen Sharing / ARD** | TCC `kTCCServiceScreenCapture`, `kickstart -settings` | Low | Identifies remote admin access |
| **SIP status per app** | Check if path starts with `/System/`, `csrutil status` | Low | Reduces injection false positives (TD-006) |
| **Sandbox profile analysis** | Parse sandbox profiles from entitlements | Medium | Identifies which apps have restricted vs unrestricted access |
| **Firewall rules** | `pfctl -sr`, Application Firewall state | Medium | Network trust boundary mapping |

### Medium Value (enhances graph richness)

| Feature | macOS Implementation | Effort | Impact |
|---|---|---|---|
| **File ACLs on sensitive paths** | `ls -le` on TCC.db, Keychain, /etc/ | Medium | Models who can read/write critical files |
| **Login sessions** | `who`, `last`, `w` commands | Low | Identifies active users (temporal) |
| **Process list** (point-in-time) | `ps aux` → which apps are running | Low | Correlates running state with graph |
| **Notarization status** | `spctl -a -t exec -vvv` | Low | Additional trust signal |
| **Privacy Preferences** (TCC 2.0) | Full TCC service enumeration including new Tahoe services | Low | Already partially implemented |
| **Gatekeeper state** | `spctl --status` | Low | System-wide security posture |

### Low Value (nice-to-have, diminishing returns)

| Feature | macOS Implementation | Effort | Impact |
|---|---|---|---|
| **DNS cache / mDNS services** | `dscacheutil -cachedump`, `dns-sd -B` | Medium | Network topology |
| **Bluetooth paired devices** | System Preferences plist | Low | Physical access vectors |
| **Installed browser extensions** | Walk `~/Library/Application Support/<browser>/Extensions/` | Medium | Extension-based attack surface |
| **Time Machine backup ACLs** | `tmutil listbackups` + ACL check | Medium | Backup-based data access |
| **iCloud state** | `defaults read MobileMeAccounts` | Low | Cloud sync exposure |

---

## 7. Summary Scorecard

| Category | BloodHound | Rootstock | Coverage |
|---|---|---|---|
| **AD Node Types** | 15 | 0 | 0% (out of scope) |
| **Azure Node Types** | 20 | 0 | 0% (out of scope) |
| **macOS-Native Node Types** | 0 | 8 | ∞ (Rootstock-only) |
| **AD Edge Types** | 84 | 0 | 0% (out of scope) |
| **macOS Edge Types** | 0 | 11 | ∞ (Rootstock-only) |
| **Attack Path Categories (AD)** | ~15 | 0 | 0% (out of scope) |
| **Attack Path Categories (macOS)** | 0 | 13 | ∞ (Rootstock-only) |
| **Pre-built Queries** | 170+ | 23 | — (different domains) |
| **Collector Data Sources** | 12+ (AD/Azure/LDAP/SMB) | 7 (macOS-native APIs) | — (different domains) |
| **Interactive UI** | Full web UI (React/Sigma.js) | Neo4j Browser only | ⚠️ Gap |
| **REST API** | Full RBAC API | None | ❌ Gap |
| **Report Generation** | None built-in | Markdown + HTML + Graphviz | ✅ Rootstock advantage |
| **Multi-platform** | AD + Azure + GitHub + Okta + Jamf | macOS only | ❌ By design |
| **OpenGraph extensibility** | 31 collectors in library | N/A | ❌ Gap |

### Key Insight

BloodHound and Rootstock are **complementary, not competing**. BloodHound models identity-centric trust (AD users → groups → permissions). Rootstock models app-centric trust (macOS apps → TCC → entitlements → injection). The overlap is zero — every attack path Rootstock discovers is invisible to BloodHound, and vice versa. The strategic opportunity is integration via BloodHound's OpenGraph framework (see `docs/paper/paper-skeleton.md` §7).
