-- Drop issue tracker tables

DROP POLICY IF EXISTS "vulnerability_tickets_tenant_isolation" ON vulnerability_tickets;
DROP POLICY IF EXISTS "issue_tracker_connections_tenant_isolation" ON issue_tracker_connections;

DROP TABLE IF EXISTS vulnerability_tickets;
DROP TABLE IF EXISTS issue_tracker_connections;
