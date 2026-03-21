"""
infer_esf.py — Infer Endpoint Security Framework client blinding paths.

Apps with com.apple.developer.endpoint-security.client entitlement are ESF
clients — they receive system-wide security events (process exec, file open,
network connect, etc.). If an ESF client is injectable, an attacker can
disable or manipulate security monitoring.

Edge: InjectableApp -[:CAN_BLIND_MONITORING {inferred: true}]-> SystemExtension
      (where the SystemExtension is of type endpoint_security)
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID

_ESF_ENTITLEMENT = "com.apple.developer.endpoint-security.client"


def infer(session: Session) -> int:
    """
    Infer CAN_BLIND_MONITORING edges from injectable apps with ESF entitlement
    to SystemExtension nodes of type endpoint_security.

    An injectable ESF client can be hijacked to suppress or falsify security
    event reporting, blinding EDR/monitoring solutions.

    Returns the number of edges created or merged. Idempotent.
    """
    result = session.run(
        """
        MATCH (a:Application)-[:HAS_ENTITLEMENT]->(:Entitlement {name: $esf_ent})
        WHERE size(a.injection_methods) > 0
          AND a.bundle_id <> $attacker_id
        WITH DISTINCT a
        MATCH (se:SystemExtension {extension_type: 'endpoint_security', enabled: true})
        MERGE (a)-[r:CAN_BLIND_MONITORING]->(se)
        SET r.inferred = true,
            r.reason = 'injectable_esf_client'
        RETURN count(r) AS n
        """,
        esf_ent=_ESF_ENTITLEMENT,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]
