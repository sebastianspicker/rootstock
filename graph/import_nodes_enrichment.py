"""import_nodes_enrichment.py — Enrichment node imports (processes, ACLs, user details, bluetooth)."""

from __future__ import annotations

import logging

from neo4j import Session

from models import (
    RunningProcessData, FileACLData, UserDetailData, BluetoothDeviceData,
)

logger = logging.getLogger(__name__)


def import_running_processes(
    session: Session, processes: list[RunningProcessData]
) -> int:
    """
    Set is_running = true on Application nodes matching running processes.
    Sets is_running = false on all remaining Application nodes.
    Returns count of applications flagged as running.
    """
    count = 0

    if processes:
        bundle_ids = list({p.bundle_id for p in processes if p.bundle_id})
        if bundle_ids:
            result = session.run(
                """
                UNWIND $bundle_ids AS bid
                MATCH (a:Application {bundle_id: bid})
                SET a.is_running = true
                RETURN count(a) AS n
                """,
                bundle_ids=bundle_ids,
            )
            count = result.single()["n"]

    # Initialize remaining apps to false (not null)
    session.run(
        """
        MATCH (a:Application)
        WHERE a.is_running IS NULL
        SET a.is_running = false
        """
    )

    return count


def import_file_acls(
    session: Session, file_acls: list[FileACLData]
) -> int:
    """
    Import CriticalFile nodes from file ACL data.
    Returns count of nodes created/merged.
    """
    if not file_acls:
        return 0

    records = [
        {
            "path": f.path,
            "owner": f.owner,
            "group": f.group,
            "mode": f.mode,
            "acl_entries": f.acl_entries,
            "is_sip_protected": f.is_sip_protected,
            "is_writable_by_non_root": f.is_writable_by_non_root,
            "category": f.category,
        }
        for f in file_acls
    ]

    result = session.run(
        """
        UNWIND $records AS r
        MERGE (cf:CriticalFile {path: r.path})
        SET cf.owner = r.owner,
            cf.group = r.group,
            cf.mode = r.mode,
            cf.acl_entries = r.acl_entries,
            cf.is_sip_protected = r.is_sip_protected,
            cf.is_writable_by_non_root = r.is_writable_by_non_root,
            cf.category = r.category
        RETURN count(cf) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def import_user_details(
    session: Session, user_details: list[UserDetailData]
) -> int:
    """
    Enrich existing User nodes with extended profile data (shell, home_dir, is_hidden).
    Returns count of users enriched.
    """
    if not user_details:
        return 0

    records = [
        {
            "name": u.name,
            "shell": u.shell,
            "home_dir": u.home_dir,
            "is_hidden": u.is_hidden,
            "is_ad_user": u.is_ad_user,
        }
        for u in user_details
    ]

    result = session.run(
        """
        UNWIND $records AS r
        MERGE (u:User {name: r.name})
        SET u.shell = r.shell,
            u.home_dir = r.home_dir,
            u.is_hidden = r.is_hidden,
            u.is_ad_user = r.is_ad_user
        RETURN count(u) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def import_bluetooth_devices(
    session: Session, devices: list[BluetoothDeviceData], hostname: str
) -> tuple[int, int]:
    """
    MERGE BluetoothDevice nodes and PAIRED_WITH edges to the Computer node.
    Returns (device_count, paired_with_edges).
    """
    if not devices:
        return 0, 0

    records = [
        {
            "address": d.address,
            "name": d.name,
            "device_type": d.device_type,
            "connected": d.connected,
        }
        for d in devices
    ]

    # MERGE BluetoothDevice nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (bt:BluetoothDevice {address: r.address})
        SET bt.name        = r.name,
            bt.device_type = r.device_type,
            bt.connected   = r.connected
        """,
        records=records,
    )

    # PAIRED_WITH: BluetoothDevice → Computer
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (bt:BluetoothDevice {address: r.address})
        MATCH (c:Computer {hostname: $hostname})
        MERGE (bt)-[rel:PAIRED_WITH]->(c)
        RETURN count(rel) AS n
        """,
        records=records,
        hostname=hostname,
    )
    edges = result.single()["n"]

    return len(devices), edges
