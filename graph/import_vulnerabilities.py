#!/usr/bin/env python3
"""
import_vulnerabilities.py — Import Vulnerability and AttackTechnique nodes into Neo4j.

Reads the enriched CVE registry (static + cached EPSS/KEV/NVD data) and creates:
  - (:Vulnerability) nodes with EPSS, KEV, CVSS, CVSS vector properties
  - (:AttackTechnique) nodes with tactic/name
  - (:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(:AttackTechnique) edges
  - (:Application)-[:AFFECTED_BY]->(:Vulnerability) edges via two-tier matching:
      Tier 1 (precise): bundle ID + version range match
      Tier 2 (category fallback): existing category-based heuristic matching

Usage:
    python3 graph/import_vulnerabilities.py [--neo4j bolt://localhost:7687]

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys

from neo4j_connection import add_neo4j_args, connect_from_args
from cve_reference import _REGISTRY, AttackContext, CveEntry
from cve_enrichment import enrich_registry, EnrichedCveEntry
from version_matcher import (
    extract_macos_max_version,
    is_affected,
)


# ── Category -> Cypher match patterns ────────────────────────────────────────
#
# Each maps a CVE registry category to a Cypher WHERE clause that identifies
# which Application nodes are "affected by" that category's vulnerabilities.
# This reuses the same matching logic as report_assembly's active_categories.

_CATEGORY_MATCH: dict[str, str] = {
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
    "sip_bypass": """
        EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement)
            WHERE app.team_id IS NOT NULL AND app.team_id <> 'com.apple'
        }
        AND size(app.injection_methods) > 0
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
    "kerberos": """
        EXISTS {
            MATCH (app)-[:HAS_KERBEROS_CACHE]->()
        }
        OR EXISTS {
            MATCH (app)-[:HAS_KEYTAB]->()
        }
    """,
    "keychain_access": """
        EXISTS {
            MATCH (app)-[:CAN_READ_KEYCHAIN]->(:Keychain_Item)
        }
        AND size(app.injection_methods) > 0
    """,
    "kernel_escalation": """
        size(app.injection_methods) > 0
        AND EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement {is_private: true})
        }
    """,
    "physical_security": """
        EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        }
    """,
    "certificate_hygiene": """
        app.signing_info_flags IS NOT NULL
    """,
    "shell_hooks": """
        EXISTS {
            MATCH (app)-[:CAN_INJECT_SHELL]->()
        }
    """,
    "file_acl_escalation": """
        EXISTS {
            MATCH (app)-[:CAN_WRITE]->(:CriticalFile)
        }
    """,
    "esf_bypass": """
        EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement)
            WHERE app.name CONTAINS 'Security' OR app.name CONTAINS 'Endpoint'
        }
        AND size(app.injection_methods) > 0
    """,
    "sandbox_escape": """
        app.sandboxed = false
        AND size(app.injection_methods) > 0
    """,
    "mdm_risk": """
        EXISTS {
            MATCH (app)-[:MDM_OVERGRANT]->()
        }
    """,
    "running_processes": """
        app.is_running = true
        AND size(app.injection_methods) > 0
    """,
    "icloud_risk": """
        EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement)
            WHERE app.bundle_id IS NOT NULL
        }
        AND size(app.injection_methods) > 0
    """,
    "blastpass_class": """
        size(app.injection_methods) > 0
    """,
    "firewall_exposure": """
        EXISTS {
            MATCH (app)-[:HAS_FIREWALL_RULE]->(:FirewallPolicy)
        }
        AND size(app.injection_methods) > 0
    """,
}


# ── Import functions ─────────────────────────────────────────────────────

def import_vulnerability_nodes(session) -> int:
    """MERGE Vulnerability nodes from the enriched CVE registry."""
    enriched = enrich_registry()

    count = 0
    for entry in enriched.values():
        cve = entry.base
        result = session.run(
            """
            MERGE (v:Vulnerability {cve_id: $cve_id})
            SET v.title = $title,
                v.cvss_score = $cvss_score,
                v.epss_score = $epss_score,
                v.epss_percentile = $epss_percentile,
                v.in_kev = $in_kev,
                v.kev_date_added = $kev_date_added,
                v.exploitation_status = $exploitation_status,
                v.attack_complexity = $attack_complexity,
                v.affected_versions = $affected_versions,
                v.patched_version = $patched_version,
                v.description = $description,
                v.reference_url = $reference_url,
                v.kev_ransomware = $kev_ransomware,
                v.cwe_ids = $cwe_ids,
                v.cvss_vector = $cvss_vector
            RETURN count(v) AS n
            """,
            cve_id=cve.cve_id,
            title=cve.title,
            cvss_score=cve.cvss_score,
            epss_score=entry.epss_score,
            epss_percentile=entry.epss_percentile,
            in_kev=entry.in_kev,
            kev_date_added=entry.kev_date_added,
            exploitation_status=cve.exploitation_status,
            attack_complexity=cve.attack_complexity,
            affected_versions=cve.affected_versions,
            patched_version=cve.patched_version,
            description=cve.description,
            reference_url=cve.reference_url,
            kev_ransomware=entry.kev_ransomware,
            cwe_ids=list(cve.cwe_ids),
            cvss_vector=entry.cvss_vector,
        )
        count += result.single()["n"]

    return count


def import_technique_nodes(session) -> int:
    """MERGE AttackTechnique nodes from the registry."""
    seen: set[str] = set()
    count = 0

    for ctx in _REGISTRY.values():
        for tech in ctx.techniques:
            if tech.technique_id in seen:
                continue
            seen.add(tech.technique_id)

            result = session.run(
                """
                MERGE (t:AttackTechnique {technique_id: $technique_id})
                SET t.name = $name,
                    t.tactic = $tactic
                RETURN count(t) AS n
                """,
                technique_id=tech.technique_id,
                name=tech.name,
                tactic=tech.tactic,
            )
            count += result.single()["n"]

    return count


def import_technique_edges(session) -> int:
    """Create (:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(:AttackTechnique) edges."""
    count = 0
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            for tech in ctx.techniques:
                result = session.run(
                    """
                    MATCH (v:Vulnerability {cve_id: $cve_id})
                    MATCH (t:AttackTechnique {technique_id: $technique_id})
                    MERGE (v)-[:MAPS_TO_TECHNIQUE]->(t)
                    RETURN count(*) AS n
                    """,
                    cve_id=cve.cve_id,
                    technique_id=tech.technique_id,
                )
                count += result.single()["n"]

    return count


# ── Two-tier AFFECTED_BY matching ────────────────────────────────────────

def _has_macos_version_constraint(affected_versions: str) -> bool:
    """Check if the affected_versions string contains a macOS version pattern."""
    return extract_macos_max_version(affected_versions) is not None


def _collect_precise_cves() -> list[CveEntry]:
    """Return all CVEs that have affected_bundle_ids set (Tier 1 candidates)."""
    seen: set[str] = set()
    result: list[CveEntry] = []
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.affected_bundle_ids and cve.cve_id not in seen:
                seen.add(cve.cve_id)
                result.append(cve)
    return result


def import_precise_affected_by_edges(session) -> int:
    """Tier 1: Create AFFECTED_BY edges for CVEs with specific bundle ID targets.

    Matches Application nodes by bundle_id, then filters by version range
    using server-side version comparison where possible.
    """
    precise_cves = _collect_precise_cves()
    if not precise_cves:
        return 0

    count = 0
    for cve in precise_cves:
        bundle_ids = list(cve.affected_bundle_ids)

        # Query apps matching the bundle IDs, returning their versions for
        # client-side version checking
        cypher = """
            MATCH (app:Application)
            WHERE app.bundle_id IN $bundle_ids
            OPTIONAL MATCH (app)-[:INSTALLED_ON]->(c:Computer)
            RETURN app.bundle_id AS bundle_id,
                   app.version AS app_version,
                   c.macos_version AS macos_version,
                   elementId(app) AS app_id
        """

        try:
            result = session.run(cypher, bundle_ids=bundle_ids)
            records = list(result)
        except Exception as e:
            print(f"  Warning: Precise match for {cve.cve_id} failed: {e}")
            continue

        is_macos = _has_macos_version_constraint(cve.affected_versions)

        for record in records:
            app_version = record["app_version"]
            macos_version = record["macos_version"]
            app_id = record["app_id"]

            # Use max_affected_version for direct version ceiling if set
            if cve.max_affected_version and app_version and not is_macos:
                from version_matcher import parse_version_tuple, version_lte
                app_v = parse_version_tuple(app_version)
                max_v = parse_version_tuple(cve.max_affected_version)
                affected = app_v is not None and max_v is not None and version_lte(app_v, max_v)
            else:
                affected = is_affected(
                    app_version=app_version,
                    affected_versions=cve.affected_versions,
                    patched_version=cve.patched_version,
                    is_macos_cve=is_macos,
                    macos_version=macos_version,
                )

            if affected:
                try:
                    edge_result = session.run(
                        """
                        MATCH (app:Application) WHERE elementId(app) = $app_id
                        MATCH (v:Vulnerability {cve_id: $cve_id})
                        MERGE (app)-[r:AFFECTED_BY]->(v)
                        SET r.match_tier = 'precise'
                        RETURN count(*) AS n
                        """,
                        app_id=app_id,
                        cve_id=cve.cve_id,
                    )
                    count += edge_result.single()["n"]
                except Exception as e:
                    print(f"  Warning: Edge creation for {cve.cve_id} failed: {e}")

    return count


def import_affected_by_edges(session) -> int:
    """Tier 2: Create AFFECTED_BY edges based on category matching (fallback).

    CVEs that already have Tier 1 (precise) edges are excluded from Tier 2
    to avoid duplicating edges for the same CVE with a weaker match tier.
    """
    # Collect CVE IDs already handled by Tier 1
    precise_cve_ids = {cve.cve_id for cve in _collect_precise_cves()}

    count = 0

    for category, ctx in _REGISTRY.items():
        if not ctx.cves:
            continue

        match_clause = _CATEGORY_MATCH.get(category)
        if not match_clause:
            continue

        # Filter out CVEs that have precise bundle ID matching
        # (they were handled in Tier 1)
        fallback_cves = [
            cve for cve in ctx.cves
            if cve.cve_id not in precise_cve_ids
        ]
        if not fallback_cves:
            continue

        cve_ids = [cve.cve_id for cve in fallback_cves]

        # Build a single Cypher query that matches apps for this category
        # and links them to all CVEs in the category
        cypher = f"""
            MATCH (app:Application)
            WHERE {match_clause}
            WITH app
            UNWIND $cve_ids AS cve_id
            MATCH (v:Vulnerability {{cve_id: cve_id}})
            MERGE (app)-[r:AFFECTED_BY]->(v)
            ON CREATE SET r.match_tier = 'category'
            RETURN count(*) AS n
        """

        try:
            result = session.run(cypher, cve_ids=cve_ids)
            count += result.single()["n"]
        except Exception as e:
            print(f"  Warning: AFFECTED_BY for category '{category}' failed: {e}")

    return count


def import_all(session) -> dict[str, int]:
    """Run the full vulnerability import pipeline."""
    vuln_count = import_vulnerability_nodes(session)
    tech_count = import_technique_nodes(session)
    maps_count = import_technique_edges(session)
    precise_count = import_precise_affected_by_edges(session)
    category_count = import_affected_by_edges(session)

    return {
        "vulnerabilities": vuln_count,
        "techniques": tech_count,
        "maps_to_technique": maps_count,
        "affected_by_precise": precise_count,
        "affected_by_category": category_count,
        "affected_by": precise_count + category_count,
    }


# ── CLI ──────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import Vulnerability and AttackTechnique nodes into Neo4j"
    )
    add_neo4j_args(parser)
    args = parser.parse_args()

    driver = connect_from_args(args)

    print("Importing vulnerability data...")
    with driver.session() as session:
        counts = import_all(session)

    driver.close()

    print(f"  Vulnerability nodes: {counts['vulnerabilities']}")
    print(f"  AttackTechnique nodes: {counts['techniques']}")
    print(f"  MAPS_TO_TECHNIQUE edges: {counts['maps_to_technique']}")
    print(f"  AFFECTED_BY edges (precise): {counts['affected_by_precise']}")
    print(f"  AFFECTED_BY edges (category): {counts['affected_by_category']}")
    print(f"  AFFECTED_BY edges (total): {counts['affected_by']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
