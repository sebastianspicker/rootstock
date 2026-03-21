"""
infer_recommendations.py — Create graph-native Recommendation nodes with edges.

Creates (:Recommendation) nodes and links them to Application nodes via
(:Application)-[:HAS_RECOMMENDATION]->(:Recommendation) edges based on
the same conditions as report_assembly.py RECOMMENDATIONS.

Also creates (:Recommendation)-[:MITIGATES]->(:AttackTechnique) edges
for recommendations that map to ATT&CK techniques.
"""

from __future__ import annotations

from neo4j import Session


# ── Recommendation definitions ───────────────────────────────────────────────
# Each entry: (key, category, text, priority, technique_ids, cypher_condition)

_RECOMMENDATIONS: list[tuple[str, str, str, str, list[str], str]] = [
    (
        "harden_runtime",
        "injectable_fda",
        "Enable Hardened Runtime for all first-party and in-house applications.",
        "critical",
        ["T1574.006"],
        """EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        } AND size(app.injection_methods) > 0""",
    ),
    (
        "library_validation",
        "injectable_fda",
        "Enable Library Validation to prevent unsigned dylib injection.",
        "critical",
        ["T1574.006"],
        """size(app.injection_methods) > 0
        AND any(m IN app.injection_methods WHERE m CONTAINS 'DYLD')""",
    ),
    (
        "audit_fda_grants",
        "injectable_fda",
        "Audit all applications with Full Disk Access — revoke unnecessary grants.",
        "critical",
        [],
        """EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        } AND size(app.injection_methods) > 0""",
    ),
    (
        "disable_electron_node",
        "electron_inheritance",
        "Disable ELECTRON_RUN_AS_NODE support in production Electron builds.",
        "high",
        ["T1574.006", "T1059.007"],
        """EXISTS { MATCH (app)-[:CHILD_INHERITS_TCC]->() }""",
    ),
    (
        "sandbox_electron",
        "electron_inheritance",
        "Sandbox Electron apps using macOS App Sandbox to limit blast radius.",
        "high",
        [],
        """EXISTS { MATCH (app)-[:CHILD_INHERITS_TCC]->() }""",
    ),
    (
        "audit_apple_events",
        "apple_events",
        "Audit Apple Event automation grants — revoke kTCCServiceAppleEvents from low-trust apps.",
        "high",
        ["T1059.002"],
        """EXISTS { MATCH (app)-[:CAN_SEND_APPLE_EVENT]->() }""",
    ),
    (
        "enable_lockdown_mode",
        "physical_security",
        "Enable Lockdown Mode on high-value targets to reduce zero-click attack surface.",
        "medium",
        ["T1200"],
        """EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        }""",
    ),
    (
        "require_notarization",
        "certificate_hygiene",
        "Require notarization for all in-house applications before deployment.",
        "high",
        ["T1553.001"],
        """app.signed = true AND (
            coalesce(app.is_certificate_expired, false) = true
            OR coalesce(app.is_adhoc_signed, false) = true
        )""",
    ),
    (
        "audit_shell_hooks",
        "shell_hooks",
        "Audit writable shell configuration files — restrict write access to owning user.",
        "high",
        ["T1546.004"],
        """EXISTS { MATCH (app)-[:CAN_INJECT_SHELL]->() }""",
    ),
    (
        "harden_esf_clients",
        "esf_bypass",
        "Harden injectable apps with ESF entitlements — these can blind EDR monitoring.",
        "critical",
        ["T1014", "T1562.001"],
        """EXISTS { MATCH (app)-[:CAN_BLIND_MONITORING]->() }""",
    ),
    (
        "patch_sandbox_escapes",
        "sandbox_escape",
        "Prioritise patching sandbox escape CVEs — sandbox escapes enable full system access.",
        "critical",
        ["T1612"],
        """coalesce(app.is_sandboxed, false) = false AND size(app.injection_methods) > 0""",
    ),
    (
        "review_mdm_pppc",
        "mdm_risk",
        "Review MDM PPPC profiles for overgrants to scripting interpreters.",
        "high",
        ["T1548.004"],
        """EXISTS { MATCH (app)-[:MDM_OVERGRANT]->() }""",
    ),
    (
        "restrict_remote_access",
        "lateral_movement",
        "Restrict SSH and Screen Sharing access to authorised users via MDM.",
        "high",
        ["T1021.004", "T1021.005"],
        """EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        }""",
    ),
    (
        "audit_file_acls",
        "file_acl_escalation",
        "Audit file ACLs on security-critical files — remove non-root write ACEs.",
        "high",
        ["T1098"],
        """EXISTS { MATCH (app)-[:CAN_WRITE]->(:CriticalFile) }""",
    ),
    (
        "audit_sudoers",
        "authorization_hardening",
        "Audit sudoers NOPASSWD entries — remove unnecessary passwordless sudo rules.",
        "medium",
        ["T1548.003"],
        """EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        }""",
    ),
    (
        "gatekeeper_enforcement",
        "gatekeeper_bypass",
        "Investigate unquarantined non-system applications that bypassed Gatekeeper.",
        "high",
        ["T1553.001"],
        """EXISTS { MATCH (app)-[:BYPASSED_GATEKEEPER]->() }""",
    ),
    (
        "monitor_running_injectable",
        "running_processes",
        "Monitor running injectable processes with active TCC grants.",
        "high",
        ["T1574.006"],
        """app.is_running = true AND size(app.injection_methods) > 0""",
    ),
]


def infer(session: Session) -> int:
    """
    Create Recommendation nodes and HAS_RECOMMENDATION + MITIGATES edges.

    Returns the total number of HAS_RECOMMENDATION edges created.
    """
    total_edges = 0

    # Step 1: MERGE all Recommendation nodes
    for key, category, text, priority, technique_ids, _ in _RECOMMENDATIONS:
        session.run(
            """
            MERGE (r:Recommendation {key: $key})
            SET r.category = $category,
                r.text     = $text,
                r.priority = $priority
            """,
            key=key,
            category=category,
            text=text,
            priority=priority,
        )

        # Step 2: Create MITIGATES edges to AttackTechnique nodes
        for tid in technique_ids:
            session.run(
                """
                MATCH (r:Recommendation {key: $key})
                MATCH (t:AttackTechnique {technique_id: $tid})
                MERGE (r)-[:MITIGATES]->(t)
                """,
                key=key,
                tid=tid,
            )

    # Step 3: Create HAS_RECOMMENDATION edges from matching Applications
    for key, _, _, _, _, condition in _RECOMMENDATIONS:
        cypher = f"""
            MATCH (app:Application)
            WHERE {condition}
            MATCH (r:Recommendation {{key: $key}})
            MERGE (app)-[:HAS_RECOMMENDATION]->(r)
            RETURN count(*) AS n
        """
        try:
            result = session.run(cypher, key=key)
            total_edges += result.single()["n"]
        except Exception:
            # Skip conditions that fail (e.g., missing edge types)
            pass

    return total_edges
