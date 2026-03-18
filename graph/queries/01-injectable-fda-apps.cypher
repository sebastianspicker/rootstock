// Name: Injectable Full Disk Access Apps
// Purpose: Find apps with Full Disk Access that can be injected with attacker code
// Attack: Inject dylib into FDA app → inherit Full Disk Access → read/modify TCC.db
// Severity: Critical
// Prerequisites: import.py + infer.py must have run

MATCH (app:Application)-[:HAS_TCC_GRANT {allowed: true}]->
      (:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)
WITH app, collect(DISTINCT inj.method) AS injection_methods
RETURN app.name            AS app_name,
       app.bundle_id       AS bundle_id,
       app.path            AS path,
       app.team_id         AS team_id,
       injection_methods,
       size(injection_methods) AS method_count
ORDER BY method_count DESC, app.name ASC
