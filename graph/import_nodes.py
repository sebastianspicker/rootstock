"""
import_nodes.py — Neo4j node and relationship import functions.

All operations use MERGE (not CREATE) for idempotency: re-importing the same
scan is always safe. UNWIND is used throughout to batch operations into single
queries rather than one query per node.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from neo4j import Session

from models import ApplicationData, TCCGrantData, XPCServiceData, KeychainItemData, MDMProfileData, LaunchItemData

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def import_applications(session: Session, apps: list[ApplicationData], scan_id: str) -> int:
    """MERGE Application nodes. Returns the number of apps processed."""
    if not apps:
        return 0

    now = _now_iso()
    records = [
        {
            "bundle_id": app.bundle_id,
            "name": app.name,
            "path": app.path,
            "version": app.version,
            "team_id": app.team_id,
            "hardened_runtime": app.hardened_runtime,
            "library_validation": app.library_validation,
            "is_electron": app.is_electron,
            "is_system": app.is_system,
            "signed": app.signed,
            "injection_methods": app.injection_methods,
            "scan_id": scan_id,
            "imported_at": now,
        }
        for app in apps
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (a:Application {bundle_id: r.bundle_id})
        SET a.name             = r.name,
            a.path             = r.path,
            a.version          = r.version,
            a.team_id          = r.team_id,
            a.hardened_runtime = r.hardened_runtime,
            a.library_validation = r.library_validation,
            a.is_electron      = r.is_electron,
            a.is_system        = r.is_system,
            a.signed           = r.signed,
            a.injection_methods = r.injection_methods,
            a.scan_id          = r.scan_id,
            a.imported_at      = r.imported_at
        """,
        records=records,
    )
    return len(records)


def import_tcc_grants(
    session: Session, grants: list[TCCGrantData], scan_id: str
) -> tuple[int, int]:
    """
    MERGE TCC_Permission nodes and HAS_TCC_GRANT relationships.
    Skips grants whose client bundle_id has no matching Application node.
    Returns (grants_linked, grants_skipped).
    """
    if not grants:
        return 0, 0

    records = [
        {
            "service": g.service,
            "display_name": g.display_name,
            "client": g.client,
            "allowed": g.allowed,
            "auth_reason": g.auth_reason_label,
            "auth_value": g.auth_value,
            "scope": g.scope,
            "last_modified": g.last_modified,
            "scan_id": scan_id,
        }
        for g in grants
    ]

    # MERGE the TCC_Permission nodes (they may already exist from the seed)
    session.run(
        """
        UNWIND $records AS r
        MERGE (t:TCC_Permission {service: r.service})
        ON CREATE SET t.display_name = r.display_name
        """,
        records=records,
    )

    # Create HAS_TCC_GRANT edges only where an Application node matches the client
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {bundle_id: r.client})
        MATCH (t:TCC_Permission {service: r.service})
        MERGE (a)-[rel:HAS_TCC_GRANT {scope: r.scope}]->(t)
        SET rel.allowed       = r.allowed,
            rel.auth_reason   = r.auth_reason,
            rel.auth_value    = r.auth_value,
            rel.last_modified = r.last_modified,
            rel.scan_id       = r.scan_id
        RETURN count(rel) AS linked
        """,
        records=records,
    )
    linked = result.single()["linked"]
    skipped = len(records) - linked
    if skipped > 0:
        logger.debug("%d TCC grants had no matching Application node (path-only clients)", skipped)
    return linked, skipped


def import_entitlements(
    session: Session, apps: list[ApplicationData]
) -> tuple[int, int]:
    """
    MERGE Entitlement nodes and HAS_ENTITLEMENT relationships.
    Returns (entitlement_nodes_created_or_merged, relationships_created_or_merged).
    """
    # Flatten app → entitlement pairs, keyed by bundle_id
    records = [
        {
            "bundle_id": app.bundle_id,
            "name": ent.name,
            "is_private": ent.is_private,
            "category": ent.category,
            "is_security_critical": ent.is_security_critical,
        }
        for app in apps
        for ent in app.entitlements
    ]

    if not records:
        return 0, 0

    # MERGE Entitlement nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (e:Entitlement {name: r.name})
        SET e.is_private          = r.is_private,
            e.category            = r.category,
            e.is_security_critical = r.is_security_critical
        """,
        records=records,
    )

    # MERGE HAS_ENTITLEMENT relationships
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {bundle_id: r.bundle_id})
        MATCH (e:Entitlement {name: r.name})
        MERGE (a)-[rel:HAS_ENTITLEMENT]->(e)
        RETURN count(rel) AS rels
        """,
        records=records,
    )
    rels = result.single()["rels"]

    # Count distinct entitlement names (nodes merged)
    unique_names = len({r["name"] for r in records})
    return unique_names, rels


def import_xpc_services(
    session: Session, services: list[XPCServiceData]
) -> tuple[int, int]:
    """
    MERGE XPC_Service nodes and COMMUNICATES_WITH edges.

    COMMUNICATES_WITH edges are created when an Application has an Entitlement
    whose name exactly matches one of the service's mach_service names — indicating
    the application explicitly references that service by name.

    Returns (xpc_nodes, communicates_with_edges).
    """
    if not services:
        return 0, 0

    records = [
        {
            "label": s.label,
            "path": s.path,
            "program": s.program,
            "type": s.type,
            "user": s.user,
            "run_at_load": s.run_at_load,
            "keep_alive": s.keep_alive,
            "mach_services": s.mach_services,
            "entitlements": s.entitlements,
        }
        for s in services
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (x:XPC_Service {label: r.label})
        SET x.path          = r.path,
            x.program       = r.program,
            x.type          = r.type,
            x.user          = r.user,
            x.run_at_load   = r.run_at_load,
            x.keep_alive    = r.keep_alive,
            x.mach_services = r.mach_services,
            x.entitlements  = r.entitlements
        """,
        records=records,
    )

    # COMMUNICATES_WITH: Application has entitlement key matching a mach service name
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE size(r.mach_services) > 0
        UNWIND r.mach_services AS svc_name
        MATCH (x:XPC_Service {label: r.label})
        MATCH (a:Application)-[:HAS_ENTITLEMENT]->(e:Entitlement {name: svc_name})
        MERGE (a)-[rel:COMMUNICATES_WITH {mach_service: svc_name}]->(x)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    comm_edges = result.single()["n"]
    return len(services), comm_edges


def import_launch_items(
    session: Session, items: list[LaunchItemData]
) -> tuple[int, int, int]:
    """
    MERGE LaunchItem nodes, User nodes (for RUNS_AS), and infer graph edges.

    Edges created:
      - (Application)-[:PERSISTS_VIA]->(LaunchItem): when an app's bundle path
        is a prefix of the launch item's program path
      - (LaunchItem)-[:RUNS_AS]->(User): when the item has a user field

    Returns (launch_item_nodes, persists_via_edges, runs_as_edges).
    """
    if not items:
        return 0, 0, 0

    records = [
        {
            "label": i.label,
            "path": i.path,
            "type": i.type,
            "program": i.program,
            "run_at_load": i.run_at_load,
            "user": i.user,
        }
        for i in items
    ]

    # MERGE LaunchItem nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (l:LaunchItem {label: r.label})
        SET l.path       = r.path,
            l.type       = r.type,
            l.program    = r.program,
            l.run_at_load = r.run_at_load,
            l.user       = r.user
        """,
        records=records,
    )

    # PERSISTS_VIA: Application's bundle path is a prefix of the LaunchItem program path
    persists_result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.program IS NOT NULL
        MATCH (l:LaunchItem {label: r.label})
        MATCH (a:Application)
        WHERE r.program STARTS WITH a.path
        MERGE (a)-[rel:PERSISTS_VIA]->(l)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    persists_count = persists_result.single()["n"]

    # RUNS_AS: LaunchItem → User (MERGE User node by name)
    runs_result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.user IS NOT NULL
        MATCH (l:LaunchItem {label: r.label})
        MERGE (u:User {name: r.user})
        MERGE (l)-[rel:RUNS_AS]->(u)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    runs_count = runs_result.single()["n"]

    return len(items), persists_count, runs_count


def import_mdm_profiles(
    session: Session, profiles: list[MDMProfileData]
) -> tuple[int, int]:
    """
    MERGE MDM_Profile nodes and CONFIGURES relationships to TCC_Permission nodes.

    CONFIGURES edges carry bundle_id and allowed properties so callers can
    identify which applications have MDM-managed TCC access and whether it was
    granted or denied.

    Returns (mdm_profile_nodes, configures_edges).
    """
    if not profiles:
        return 0, 0

    profile_records = [
        {
            "identifier": p.identifier,
            "display_name": p.display_name,
            "organization": p.organization,
            "install_date": p.install_date,
        }
        for p in profiles
    ]

    # MERGE MDM_Profile nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (m:MDM_Profile {identifier: r.identifier})
        SET m.display_name = r.display_name,
            m.organization = r.organization,
            m.install_date = r.install_date
        """,
        records=profile_records,
    )

    # Flatten TCC policies across all profiles
    policy_records = [
        {
            "profile_identifier": p.identifier,
            "service": policy.service,
            "bundle_id": policy.client_bundle_id,
            "allowed": policy.allowed,
        }
        for p in profiles
        for policy in p.tcc_policies
    ]

    if not policy_records:
        return len(profiles), 0

    # CONFIGURES: MDM_Profile → TCC_Permission
    # Also MERGE the TCC_Permission node in case it doesn't exist yet.
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (m:MDM_Profile {identifier: r.profile_identifier})
        MERGE (t:TCC_Permission {service: r.service})
        ON CREATE SET t.display_name = r.service
        MERGE (m)-[rel:CONFIGURES {bundle_id: r.bundle_id}]->(t)
        SET rel.allowed = r.allowed
        RETURN count(rel) AS n
        """,
        records=policy_records,
    )
    edges = result.single()["n"]

    return len(profiles), edges


def import_keychain_items(
    session: Session, items: list[KeychainItemData]
) -> tuple[int, int]:
    """
    MERGE Keychain_Item nodes and CAN_READ_KEYCHAIN relationships.

    CAN_READ_KEYCHAIN is created when an Application's bundle_id appears in
    a keychain item's trusted_apps list (i.e., the app is explicitly granted
    access without prompting the user).

    Returns (keychain_item_nodes, can_read_keychain_edges).
    """
    if not items:
        return 0, 0

    records = [
        {
            "label": item.label,
            "kind": item.kind,
            "service": item.service,
            "access_group": item.access_group,
            "trusted_apps": item.trusted_apps,
        }
        for item in items
    ]

    # MERGE Keychain_Item nodes (label + kind forms the composite identity)
    session.run(
        """
        UNWIND $records AS r
        MERGE (k:Keychain_Item {label: r.label, kind: r.kind})
        SET k.service      = r.service,
            k.access_group = r.access_group
        """,
        records=records,
    )

    # CAN_READ_KEYCHAIN: Application → Keychain_Item where bundle_id is in trusted_apps
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE size(r.trusted_apps) > 0
        UNWIND r.trusted_apps AS bundle_id
        MATCH (a:Application {bundle_id: bundle_id})
        MATCH (k:Keychain_Item {label: r.label, kind: r.kind})
        MERGE (a)-[rel:CAN_READ_KEYCHAIN]->(k)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    edges = result.single()["n"]

    return len(records), edges


def import_signed_by_team(session: Session) -> int:
    """
    Create SIGNED_BY_SAME_TEAM edges between all Application pairs sharing a team_id.
    Groups by team_id first to avoid an O(N^2) cross-join across all applications.
    Edges go from lexicographically smaller bundle_id to larger to avoid duplicates.
    Returns number of relationships created or merged.
    """
    result = session.run(
        """
        MATCH (a:Application)
        WHERE a.team_id IS NOT NULL
        WITH a.team_id AS tid, collect(a) AS apps
        WHERE size(apps) > 1
        UNWIND apps AS a
        UNWIND apps AS b
        WITH a, b WHERE a.bundle_id < b.bundle_id
        MERGE (a)-[r:SIGNED_BY_SAME_TEAM]->(b)
        SET r.team_id = a.team_id
        RETURN count(r) AS rels
        """
    )
    return result.single()["rels"]
