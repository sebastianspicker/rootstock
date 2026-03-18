"""
infer_injection.py — Infer CAN_INJECT_INTO relationships.

Creates edges from a synthetic `attacker.payload` node to any Application that:
  - Has at least one allowed TCC grant (making it a valuable target), AND
  - Is missing library validation (`library_validation = false`), OR
  - Is missing hardened runtime (`hardened_runtime = false`), OR
  - Has the allow-dyld-environment-variables entitlement

All inferred edges carry `{inferred: true}` to distinguish them from explicit data.
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID, ATTACKER_NAME, ALLOW_DYLD_ENTITLEMENT


def ensure_attacker_node(session: Session) -> None:
    """Create (or match) the synthetic attacker.payload node. Idempotent."""
    session.run(
        """
        MERGE (a:Application {bundle_id: $bundle_id})
        ON CREATE SET a.name = $name, a.is_system = false,
                      a.hardened_runtime = false, a.library_validation = false,
                      a.is_electron = false, a.signed = false,
                      a.injection_methods = [], a.inferred = true
        """,
        bundle_id=ATTACKER_BUNDLE_ID,
        name=ATTACKER_NAME,
    )


def _infer_missing_library_validation(session: Session) -> int:
    result = session.run(
        """
        MATCH (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        WITH DISTINCT target
        WHERE target.library_validation = false
          AND target.bundle_id <> $attacker_id
        MATCH (attacker:Application {bundle_id: $attacker_id})
        MERGE (attacker)-[r:CAN_INJECT_INTO {method: 'missing_library_validation'}]->(target)
        SET r.inferred = true
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]


def _infer_dyld_insert(session: Session) -> int:
    result = session.run(
        """
        MATCH (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        WITH DISTINCT target
        WHERE target.hardened_runtime = false
          AND target.bundle_id <> $attacker_id
        MATCH (attacker:Application {bundle_id: $attacker_id})
        MERGE (attacker)-[r:CAN_INJECT_INTO {method: 'dyld_insert'}]->(target)
        SET r.inferred = true
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]


def _infer_dyld_via_entitlement(session: Session) -> int:
    result = session.run(
        """
        MATCH (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        MATCH (target)-[:HAS_ENTITLEMENT]->(:Entitlement {name: $ent})
        WITH DISTINCT target
        WHERE target.bundle_id <> $attacker_id
        MATCH (attacker:Application {bundle_id: $attacker_id})
        MERGE (attacker)-[r:CAN_INJECT_INTO {method: 'dyld_insert_via_entitlement'}]->(target)
        SET r.inferred = true
        RETURN count(r) AS n
        """,
        ent=ALLOW_DYLD_ENTITLEMENT,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]


def infer(session: Session) -> int:
    """
    Infer all CAN_INJECT_INTO relationships. Returns total edge count.
    Idempotent: uses MERGE, safe to re-run.
    """
    ensure_attacker_node(session)
    n = 0
    n += _infer_missing_library_validation(session)
    n += _infer_dyld_insert(session)
    n += _infer_dyld_via_entitlement(session)
    return n
