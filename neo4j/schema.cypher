// neo4j/schema.cypher — ATHENA v2.0 Knowledge Graph Schema

// Constraints (unique identifiers)
CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE;
CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT subdomain_name IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE;
CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE;
CREATE CONSTRAINT engagement_id IF NOT EXISTS FOR (e:Engagement) REQUIRE e.id IS UNIQUE;
CREATE CONSTRAINT credential_id IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT exploit_result_id IF NOT EXISTS FOR (er:ExploitResult) REQUIRE er.id IS UNIQUE;
CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (ep:EvidencePackage) REQUIRE ep.id IS UNIQUE;

// Indexes (query performance)
CREATE INDEX host_engagement IF NOT EXISTS FOR (h:Host) ON (h.engagement_id);
CREATE INDEX service_port IF NOT EXISTS FOR (s:Service) ON (s.port);
CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);
CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity);
CREATE INDEX engagement_status IF NOT EXISTS FOR (e:Engagement) ON (e.status);

// Node property type hints (documentation only — Neo4j 5.x)
// :Host {ip, hostname, os, os_version, status, first_seen, last_seen, engagement_id}
// :Service {port, protocol, name, version, banner, state, host_ip, engagement_id}
// :Domain {name, registrar, nameservers, whois_data, engagement_id}
// :Subdomain {name, resolved_ips, source, engagement_id}
// :URL {url, status_code, content_type, tech_stack, engagement_id}
// :Vulnerability {id, cve_id, name, description, cvss_score, severity, nuclei_template, status, engagement_id}
// :Credential {id, username, hash_type, hash_value, plaintext, source, domain, engagement_id}
// :AttackPath {id, name, steps, complexity, impact, probability, engagement_id}
// :ExploitResult {id, technique, target, success, output_hash, timestamp, agent_id, engagement_id}
// :EvidencePackage {id, type, data_hash, screenshots, http_pairs, timing_data, verified_by, engagement_id}
// :Finding {id, title, description, severity, cvss, remediation, references, status, engagement_id}
// :Engagement {id, name, client, scope, start_date, end_date, status, methodology}
// :Person {name, role, email, phone, social_profiles, source, engagement_id}
// :Organization {name, industry, size, technologies, engagement_id}
// :LeakedCredential {id, email, source_breach, password_hash, date_leaked, engagement_id}
