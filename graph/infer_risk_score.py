"""
infer_risk_score.py — Compute graph-native risk scores on Application nodes.

Runs after all other inference + tier classification to set per-node:
  - risk_score (float 0.0-10.0)
  - risk_level ("critical" / "high" / "medium" / "low")
  - attack_categories (list[str])
  - critical_finding_count, high_finding_count (int)

This makes risk data queryable via Cypher and visible in the viewer/API
without recomputing in Python at report time.
"""

from __future__ import annotations

from neo4j import Session

from constants import (
    RISK_SCORE_PROPERTY,
    RISK_LEVEL_PROPERTY,
    ATTACK_CATEGORIES_PROPERTY,
    CRITICAL_FINDING_COUNT_PROPERTY,
    HIGH_FINDING_COUNT_PROPERTY,
)


# ── Category detection queries ───────────────────────────────────────────────
# Reuses the same matching logic as import_vulnerabilities._CATEGORY_MATCH
# and report_assembly.py active_categories.

_CATEGORY_CHECKS: dict[str, str] = {
    "injectable_fda": """
        EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        }
        AND size(app.injection_methods) > 0
    """,
    "dyld_injection": """
        size(app.injection_methods) > 0
        AND any(m IN app.injection_methods WHERE m CONTAINS 'DYLD')
    """,
    "tcc_bypass": """
        EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        }
    """,
    "electron_inheritance": """
        EXISTS {
            MATCH (app)-[:CHILD_INHERITS_TCC]->()
        }
    """,
    "persistence_hijack": """
        EXISTS {
            MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem)
            WHERE li.writable = true
        }
    """,
    "xpc_exploitation": """
        EXISTS {
            MATCH (app)-[:COMMUNICATES_WITH]->(:XPC_Service)
        }
        AND size(app.injection_methods) > 0
    """,
    "apple_events": """
        EXISTS {
            MATCH (app)-[:CAN_SEND_APPLE_EVENT]->()
        }
    """,
    "accessibility_abuse": """
        EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: 'kTCCServiceAccessibility'})
        }
        AND size(app.injection_methods) > 0
    """,
    "keychain_access": """
        EXISTS {
            MATCH (app)-[:CAN_READ_KEYCHAIN]->(:Keychain_Item)
        }
        AND size(app.injection_methods) > 0
    """,
    "esf_bypass": """
        EXISTS {
            MATCH (app)-[:CAN_BLIND_MONITORING]->()
        }
    """,
    "shell_hooks": """
        EXISTS {
            MATCH (app)-[:CAN_INJECT_SHELL]->()
        }
    """,
    "sandbox_escape": """
        coalesce(app.is_sandboxed, false) = false
        AND size(app.injection_methods) > 0
    """,
    "certificate_hygiene": """
        app.signed = true
        AND (
            coalesce(app.is_certificate_expired, false) = true
            OR coalesce(app.is_adhoc_signed, false) = true
            OR app.certificate_trust_valid = false
        )
    """,
}

# Categories that count as critical findings
_CRITICAL_CATEGORIES = {
    "injectable_fda", "esf_bypass",
}

# Categories that count as high findings
_HIGH_CATEGORIES = {
    "dyld_injection", "electron_inheritance", "apple_events",
    "accessibility_abuse", "keychain_access", "xpc_exploitation",
}


# ── Scoring weights ──────────────────────────────────────────────────────────

_WEIGHT_INJECTION = 3.0       # Has injection methods
_WEIGHT_FDA = 2.0             # Has FDA grant
_WEIGHT_TCC = 1.0             # Has any TCC grant
_WEIGHT_TIER0 = 1.5           # Tier 0 classification
_WEIGHT_CVE = 1.5             # Has CVE exposure
_WEIGHT_CERT_ISSUE = 0.5      # Certificate health issue
_WEIGHT_ELECTRON = 1.0        # Electron TCC inheritance


def infer(session: Session) -> int:
    """
    Compute risk scores and attack categories for all Application nodes.

    Returns the number of Application nodes updated.
    """
    # Step 1: Compute attack_categories per app using batch queries
    # Build a single query that collects all matching categories per app
    category_cases = []
    for cat, clause in _CATEGORY_CHECKS.items():
        category_cases.append(
            f"CASE WHEN {clause} THEN '{cat}' ELSE NULL END"
        )

    cases_str = ",\n        ".join(category_cases)
    category_query = f"""
        MATCH (app:Application)
        WITH app,
        [{cases_str}] AS raw_cats
        WITH app, [c IN raw_cats WHERE c IS NOT NULL] AS categories
        SET app.{ATTACK_CATEGORIES_PROPERTY} = categories
        RETURN count(app) AS n
    """
    result = session.run(category_query)
    n_categorized = result.single()["n"]

    # Step 2: Compute finding counts
    critical_cats = list(_CRITICAL_CATEGORIES)
    high_cats = list(_HIGH_CATEGORIES)

    session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{ATTACK_CATEGORIES_PROPERTY} IS NOT NULL
        WITH app,
             size([c IN app.{ATTACK_CATEGORIES_PROPERTY} WHERE c IN $critical_cats]) AS crit,
             size([c IN app.{ATTACK_CATEGORIES_PROPERTY} WHERE c IN $high_cats]) AS high
        SET app.{CRITICAL_FINDING_COUNT_PROPERTY} = crit,
            app.{HIGH_FINDING_COUNT_PROPERTY} = high
        """,
        critical_cats=critical_cats,
        high_cats=high_cats,
    )

    # Step 3: Compute composite risk_score
    # Score components: injection methods, FDA, TCC, tier, CVEs, cert health, electron
    session.run(
        f"""
        MATCH (app:Application)
        OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {{allowed: true}}]->(:TCC_Permission {{service: 'kTCCServiceSystemPolicyAllFiles'}})
        WITH app, count(*) > 0 AS has_fda
        OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {{allowed: true}}]->(:TCC_Permission)
        WITH app, has_fda, count(*) > 0 AS has_tcc
        OPTIONAL MATCH (app)-[:AFFECTED_BY]->(:Vulnerability)
        WITH app, has_fda, has_tcc, count(*) > 0 AS has_cve
        WITH app,
             CASE WHEN size(app.injection_methods) > 0 THEN $w_inj ELSE 0.0 END +
             CASE WHEN has_fda THEN $w_fda ELSE 0.0 END +
             CASE WHEN has_tcc THEN $w_tcc ELSE 0.0 END +
             CASE WHEN app.tier = 'T0' THEN $w_tier ELSE 0.0 END +
             CASE WHEN has_cve THEN $w_cve ELSE 0.0 END +
             CASE WHEN coalesce(app.is_certificate_expired, false) = true
                  OR coalesce(app.is_adhoc_signed, false) = true
                  THEN $w_cert ELSE 0.0 END +
             CASE WHEN EXISTS {{
                 MATCH (app)-[:CHILD_INHERITS_TCC]->()
             }} THEN $w_elec ELSE 0.0 END
             AS raw_score
        SET app.{RISK_SCORE_PROPERTY} = CASE
                WHEN raw_score > 10.0 THEN 10.0
                ELSE round(raw_score * 100) / 100.0
            END,
            app.{RISK_LEVEL_PROPERTY} = CASE
                WHEN raw_score >= 7.0 THEN 'critical'
                WHEN raw_score >= 5.0 THEN 'high'
                WHEN raw_score >= 3.0 THEN 'medium'
                ELSE 'low'
            END
        """,
        w_inj=_WEIGHT_INJECTION,
        w_fda=_WEIGHT_FDA,
        w_tcc=_WEIGHT_TCC,
        w_tier=_WEIGHT_TIER0,
        w_cve=_WEIGHT_CVE,
        w_cert=_WEIGHT_CERT_ISSUE,
        w_elec=_WEIGHT_ELECTRON,
    )

    return n_categorized
