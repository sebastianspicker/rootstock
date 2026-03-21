"""
cve_reference.py — CVE and MITRE ATT&CK reference registry for Rootstock findings.

Maps Rootstock finding categories to real-world CVEs (2023-2025) and ATT&CK techniques,
enabling prioritised vulnerability context in reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CveEntry:
    """A single CVE record with scoring and patch metadata."""

    cve_id: str
    title: str
    cvss_score: float
    affected_versions: str
    patched_version: str | None
    description: str
    reference_url: str


@dataclass(frozen=True)
class AttackTechnique:
    """A MITRE ATT&CK technique reference."""

    technique_id: str
    name: str
    tactic: str


@dataclass(frozen=True)
class AttackContext:
    """Full attack context for a Rootstock finding category."""

    category: str
    techniques: list[AttackTechnique]
    cves: list[CveEntry]
    remediation_priority: str  # "Immediate" | "High" | "Medium"


# ── CVE Registry ─────────────────────────────────────────────────────────────

_CVE_2025_31191 = CveEntry(
    cve_id="CVE-2025-31191",
    title="AuthKit Keychain Injection via DYLD",
    cvss_score=8.8,
    affected_versions="macOS 15.3 and earlier",
    patched_version="macOS 15.4",
    description=(
        "A logic flaw in AuthKit allowed an attacker to inject a dylib into "
        "the AuthKit process and access keychain credentials without user consent."
    ),
    reference_url="https://support.apple.com/en-us/122373",
)

_CVE_2024_44168 = CveEntry(
    cve_id="CVE-2024-44168",
    title="Library Validation Bypass",
    cvss_score=7.5,
    affected_versions="macOS 14.6 and earlier",
    patched_version="macOS 14.7",
    description=(
        "A library validation bypass allowed an attacker to load unsigned "
        "dylibs into processes with library validation enabled."
    ),
    reference_url="https://support.apple.com/en-us/121238",
)

_CVE_2024_44133 = CveEntry(
    cve_id="CVE-2024-44133",
    title="HM Surf — Safari TCC Bypass",
    cvss_score=8.8,
    affected_versions="macOS 14.6 and earlier",
    patched_version="macOS 15",
    description=(
        "Removing TCC protection for the Safari browser directory enabled "
        "an attacker to bypass TCC, access camera/microphone, and exfiltrate "
        "browsing data without user consent."
    ),
    reference_url="https://support.apple.com/en-us/121238",
)

_CVE_2024_44131 = CveEntry(
    cve_id="CVE-2024-44131",
    title="Files.app TCC Bypass via Symlink",
    cvss_score=7.5,
    affected_versions="macOS 15 and earlier, iOS 18 and earlier",
    patched_version="macOS 15.1",
    description=(
        "A symlink handling flaw in Files.app allowed a malicious app to "
        "access sensitive user data by intercepting file operations."
    ),
    reference_url="https://support.apple.com/en-us/121564",
)

_CVE_2024_54498 = CveEntry(
    cve_id="CVE-2024-54498",
    title="Sandbox Escape via App Sandbox",
    cvss_score=8.2,
    affected_versions="macOS 15.1 and earlier",
    patched_version="macOS 15.2",
    description=(
        "A path handling issue allowed a sandboxed application to escape "
        "its sandbox and access arbitrary files on the system."
    ),
    reference_url="https://support.apple.com/en-us/121839",
)

_CVE_2023_44402 = CveEntry(
    cve_id="CVE-2023-44402",
    title="Electron contextIsolation Bypass",
    cvss_score=7.5,
    affected_versions="Electron < 27.1.0",
    patched_version="Electron 27.1.0",
    description=(
        "A bypass of Electron's contextIsolation protection allowed code "
        "running in the renderer process to access Node.js APIs."
    ),
    reference_url="https://github.com/nicedayzhu/Electron-CVE-2023-44402",
)

_CVE_2024_44243 = CveEntry(
    cve_id="CVE-2024-44243",
    title="StorageKit SIP Bypass",
    cvss_score=9.8,
    affected_versions="macOS 15.1 and earlier",
    patched_version="macOS 15.2",
    description=(
        "A flaw in StorageKit allowed a locally authenticated attacker to "
        "bypass System Integrity Protection and modify protected system files."
    ),
    reference_url="https://support.apple.com/en-us/121839",
)

_CVE_2024_44294 = CveEntry(
    cve_id="CVE-2024-44294",
    title="PackageKit SIP Bypass",
    cvss_score=7.8,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 14.7.1",
    description=(
        "A logic issue in PackageKit allowed a malicious installer to "
        "modify SIP-protected directories during package installation."
    ),
    reference_url="https://support.apple.com/en-us/121570",
)

_CVE_2024_44217 = CveEntry(
    cve_id="CVE-2024-44217",
    title="LaunchServices Permission Bypass",
    cvss_score=7.5,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 15",
    description=(
        "A permissions issue in LaunchServices allowed an app to bypass "
        "certain Privacy preferences and access restricted data."
    ),
    reference_url="https://support.apple.com/en-us/121238",
)

_CVE_2024_40781 = CveEntry(
    cve_id="CVE-2024-40781",
    title="XPC Privilege Escalation",
    cvss_score=7.8,
    affected_versions="macOS 14.5 and earlier",
    patched_version="macOS 14.6",
    description=(
        "Insufficient XPC message validation allowed a local attacker to "
        "escalate privileges via a crafted XPC message to a privileged service."
    ),
    reference_url="https://support.apple.com/en-us/120911",
)

_CVE_2024_44206 = CveEntry(
    cve_id="CVE-2024-44206",
    title="Finder AppleScript Execution",
    cvss_score=7.5,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 15",
    description=(
        "Finder could be scripted via Apple Events to perform file operations "
        "with the Finder's elevated TCC grants, enabling transitive FDA access."
    ),
    reference_url="https://support.apple.com/en-us/121238",
)

_CVE_2023_42937 = CveEntry(
    cve_id="CVE-2023-42937",
    title="Accessibility Information Disclosure",
    cvss_score=5.5,
    affected_versions="macOS 14.2 and earlier",
    patched_version="macOS 14.3",
    description=(
        "A privacy issue in Accessibility allowed an app to access sensitive "
        "user data through the Accessibility framework."
    ),
    reference_url="https://support.apple.com/en-us/120896",
)

_CVE_2024_44245 = CveEntry(
    cve_id="CVE-2024-44245",
    title="Kerberos ccache Race Condition",
    cvss_score=7.0,
    affected_versions="macOS 15.1 and earlier",
    patched_version="macOS 15.2",
    description=(
        "A race condition in Kerberos credential cache handling allowed "
        "a local attacker to read another user's ccache and impersonate them."
    ),
    reference_url="https://support.apple.com/en-us/121839",
)

_CVE_2024_44204 = CveEntry(
    cve_id="CVE-2024-44204",
    title="Keychain Unauthorized Credential Access",
    cvss_score=7.5,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 15",
    description=(
        "A logic issue allowed an application to access keychain items "
        "without the expected user prompt for credential access."
    ),
    reference_url="https://support.apple.com/en-us/121238",
)

_CVE_2025_24085 = CveEntry(
    cve_id="CVE-2025-24085",
    title="CoreMedia Use-After-Free (Actively Exploited)",
    cvss_score=9.8,
    affected_versions="macOS 15.2 and earlier",
    patched_version="macOS 15.3",
    description=(
        "A use-after-free in CoreMedia allowed a malicious application "
        "to elevate privileges. Apple confirmed active exploitation in the wild."
    ),
    reference_url="https://support.apple.com/en-us/122066",
)

_CVE_2025_24118 = CveEntry(
    cve_id="CVE-2025-24118",
    title="Kernel Race Condition Privilege Escalation",
    cvss_score=9.0,
    affected_versions="macOS 15.2 and earlier",
    patched_version="macOS 15.3",
    description=(
        "A race condition in the XNU kernel allowed a local attacker "
        "to escalate privileges to kernel level."
    ),
    reference_url="https://support.apple.com/en-us/122066",
)

_CVE_2023_42861 = CveEntry(
    cve_id="CVE-2023-42861",
    title="Login Screen Bypass",
    cvss_score=6.5,
    affected_versions="macOS 14.0 and earlier",
    patched_version="macOS 14.1",
    description=(
        "A logic issue allowed a local attacker to bypass the login screen "
        "and access the desktop without valid credentials under certain conditions."
    ),
    reference_url="https://support.apple.com/en-us/120895",
)

# ── ATT&CK Technique Registry ────────────────────────────────────────────────

_T1574_006 = AttackTechnique(
    technique_id="T1574.006",
    name="Dynamic Linker Hijacking",
    tactic="Persistence, Privilege Escalation",
)

_T1548_004 = AttackTechnique(
    technique_id="T1548.004",
    name="Elevated Execution with Prompt",
    tactic="Privilege Escalation, Defense Evasion",
)

_T1059_007 = AttackTechnique(
    technique_id="T1059.007",
    name="JavaScript",
    tactic="Execution",
)

_T1562_001 = AttackTechnique(
    technique_id="T1562.001",
    name="Disable or Modify Tools",
    tactic="Defense Evasion",
)

_T1547_011 = AttackTechnique(
    technique_id="T1547.011",
    name="Plist Modification",
    tactic="Persistence, Privilege Escalation",
)

_T1543_004 = AttackTechnique(
    technique_id="T1543.004",
    name="Launch Daemon",
    tactic="Persistence, Privilege Escalation",
)

_T1559_001 = AttackTechnique(
    technique_id="T1559.001",
    name="Component Object Model",
    tactic="Execution",
)

_T1059_002 = AttackTechnique(
    technique_id="T1059.002",
    name="AppleScript",
    tactic="Execution",
)

_T1056_002 = AttackTechnique(
    technique_id="T1056.002",
    name="GUI Input Capture",
    tactic="Collection, Credential Access",
)

_T1558 = AttackTechnique(
    technique_id="T1558",
    name="Steal or Forge Kerberos Tickets",
    tactic="Credential Access",
)

_T1555_001 = AttackTechnique(
    technique_id="T1555.001",
    name="Keychain",
    tactic="Credential Access",
)

_T1068 = AttackTechnique(
    technique_id="T1068",
    name="Exploitation for Privilege Escalation",
    tactic="Privilege Escalation",
)

_T1548_003 = AttackTechnique(
    technique_id="T1548.003",
    name="Sudo and Sudo Caching",
    tactic="Privilege Escalation, Defense Evasion",
)

_T1200 = AttackTechnique(
    technique_id="T1200",
    name="Hardware Additions",
    tactic="Initial Access",
)

_T1537 = AttackTechnique(
    technique_id="T1537",
    name="Transfer Data to Cloud Account",
    tactic="Exfiltration",
)

# ── Attack Context Registry ──────────────────────────────────────────────────

_REGISTRY: dict[str, AttackContext] = {
    "dyld_injection": AttackContext(
        category="dyld_injection",
        techniques=[_T1574_006],
        cves=[_CVE_2025_31191, _CVE_2024_44168],
        remediation_priority="Immediate",
    ),
    "injectable_fda": AttackContext(
        category="injectable_fda",
        techniques=[_T1574_006],
        cves=[_CVE_2025_31191, _CVE_2024_44168],
        remediation_priority="Immediate",
    ),
    "tcc_bypass": AttackContext(
        category="tcc_bypass",
        techniques=[_T1548_004],
        cves=[_CVE_2024_44133, _CVE_2024_44131, _CVE_2024_54498],
        remediation_priority="Immediate",
    ),
    "electron_inheritance": AttackContext(
        category="electron_inheritance",
        techniques=[_T1574_006, _T1059_007],
        cves=[_CVE_2023_44402],
        remediation_priority="High",
    ),
    "sip_bypass": AttackContext(
        category="sip_bypass",
        techniques=[_T1562_001],
        cves=[_CVE_2024_44243, _CVE_2024_44294],
        remediation_priority="Immediate",
    ),
    "persistence_hijack": AttackContext(
        category="persistence_hijack",
        techniques=[_T1547_011, _T1543_004],
        cves=[_CVE_2024_44217],
        remediation_priority="High",
    ),
    "xpc_exploitation": AttackContext(
        category="xpc_exploitation",
        techniques=[_T1559_001],
        cves=[_CVE_2024_40781],
        remediation_priority="High",
    ),
    "apple_events": AttackContext(
        category="apple_events",
        techniques=[_T1059_002],
        cves=[_CVE_2024_44206],
        remediation_priority="High",
    ),
    "accessibility_abuse": AttackContext(
        category="accessibility_abuse",
        techniques=[_T1056_002],
        cves=[_CVE_2023_42937],
        remediation_priority="High",
    ),
    "kerberos": AttackContext(
        category="kerberos",
        techniques=[_T1558],
        cves=[_CVE_2024_44245],
        remediation_priority="High",
    ),
    "keychain_access": AttackContext(
        category="keychain_access",
        techniques=[_T1555_001],
        cves=[_CVE_2024_44204],
        remediation_priority="High",
    ),
    "kernel_escalation": AttackContext(
        category="kernel_escalation",
        techniques=[_T1068],
        cves=[_CVE_2025_24085, _CVE_2025_24118],
        remediation_priority="Immediate",
    ),
    "authorization_hardening": AttackContext(
        category="authorization_hardening",
        techniques=[_T1548_003],
        cves=[],
        remediation_priority="Medium",
    ),
    "physical_security": AttackContext(
        category="physical_security",
        techniques=[_T1200],
        cves=[_CVE_2023_42861],
        remediation_priority="Medium",
    ),
    "icloud_risk": AttackContext(
        category="icloud_risk",
        techniques=[_T1537],
        cves=[],
        remediation_priority="Medium",
    ),
}


# ── Public API ────────────────────────────────────────────────────────────────

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+")


def get_context(category: str) -> AttackContext | None:
    """Return the AttackContext for a finding category, or None if unknown."""
    return _REGISTRY.get(category)


def get_contexts_for_query(query: dict) -> list[AttackContext]:
    """
    Return AttackContexts relevant to a query descriptor.

    Looks up by CVE IDs in the query's ``cve`` field, matching against
    all registry entries.
    """
    cve_field = query.get("cve", "")
    if not cve_field:
        return []

    query_cves = set(_CVE_ID_RE.findall(cve_field))
    if not query_cves:
        return []

    matches: list[AttackContext] = []
    for ctx in _REGISTRY.values():
        ctx_cves = {c.cve_id for c in ctx.cves}
        if ctx_cves & query_cves:
            matches.append(ctx)
    return matches


def get_all_critical_cves(min_cvss: float = 8.0) -> list[CveEntry]:
    """Return all CVEs at or above *min_cvss*, sorted by CVSS descending."""
    seen: set[str] = set()
    result: list[CveEntry] = []
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.cvss_score >= min_cvss and cve.cve_id not in seen:
                seen.add(cve.cve_id)
                result.append(cve)
    result.sort(key=lambda c: c.cvss_score, reverse=True)
    return result
