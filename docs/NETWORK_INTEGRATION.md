# Network Integration Guide

This guide explains how to deploy Aegis Sentinel inside a company network and connect it to existing security infrastructure.

## Integration Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                        Corporate Network                         │
│                                                                  │
│  ┌──────────┐   syslog    ┌─────────────┐   API    ┌─────────┐ │
│  │ Firewalls│────────────►│ Aegis       │◄────────│ LLM     │ │
│  │ Routers  │   NetFlow   │ Sentinel    │  ingest  │ Gateway │ │
│  └──────────┘             │             │          └─────────┘ │
│                            │  :8080      │                      │
│  ┌──────────┐   Falco     │             │   webhook  ┌───────┐ │
│  │ K8s /    │────────────►│             │───────────►│ SIEM  │ │
│  │ Docker   │   runtime   └──────┬──────┘            └───────┘ │
│  └──────────┘                    │                              │
│                                  │ iptables (optional)          │
│                            ┌─────▼─────┐                        │
│                            │ Blocked   │                        │
│                            │ IPs       │                        │
│                            └───────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

## 1. LLM / AI Gateway Integration

Place Aegis in front of or beside your LLM gateway. Every user prompt passes through `/ingest/prompt`:

```bash
curl -X POST http://aegis.internal:8080/ingest/prompt \
  -H "X-API-Key: $AEGIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "<user prompt text>",
    "entity_id": "prod-llm-gateway",
    "session_id": "<session-uuid>",
    "auto_respond": false
  }'
```

**Response handling:**

| Field | Action |
|-------|--------|
| `threat_detected: true` | Block or flag request upstream |
| `alerts` | Forward to SIEM via `/alerts` poll or webhook |
| `auto_respond: true` | SOAR executed `block_llm_request` playbook |

Also integrate:

- `/ingest/agent-tool` — AI agent frameworks (LangChain, AutoGPT)
- `/ingest/rag-chunk` — vector DB retrieval pipeline
- `/ingest/image` — multimodal/VLM pipelines

## 2. Network Sensor Integration

### NetFlow / Zeek / Suricata → `/ingest/flow`

```bash
curl -X POST http://aegis.internal:8080/ingest/flow \
  -H "X-API-Key: $AEGIS_API_KEY" \
  -d '{"src_ip":"10.1.2.3","dst_port":22,"protocol":"tcp","bytes_sent":64}'
```

### DNS logs → `/ingest/dns`

Forward Pi-hole, BIND, or firewall DNS logs. IOC match against `seed_iocs.json` and live IOC table.

### Syslog → automatic collection

The API lifespan starts `SyslogCollector` which tails `/var/log/aegis-sample.log` (or configure path). For production, point rsyslog:

```
*.* @@aegis.internal:514
```

Map to `/ingest/log`:

```bash
curl -X POST .../ingest/log \
  -d '{"host_id":"fw-01","log_line":"Failed password for admin from 203.0.113.50"}'
```

## 3. Endpoint / Host Integration

### File hash IOC check

EDR or file integrity monitor sends SHA-256:

```bash
curl -X POST .../ingest/hash \
  -d '{"host_id":"ws-042","file_hash":"abc123...","file_path":"/tmp/malware.exe"}'
```

### Host logs

SSH auth, sudo, and process execution logs via `/ingest/log`.

## 4. Container Runtime (Falco)

Configure Falco HTTP output to POST to `/ingest/runtime`:

```yaml
# falco.yaml snippet
http_output:
  enabled: true
  url: http://aegis.internal:8080/ingest/runtime
  user_agent: falco/0.37
```

Wrap with a small sidecar that adds `X-API-Key` header.

## 5. SIEM / SOAR Export

### Polling model (simplest)

```bash
# Cron every 60s
curl -s -H "X-API-Key: $KEY" http://aegis:8080/alerts?limit=100 | \
  jq -c '.[]' | send-to-splunk-or-elastic
```

### Alert schema for SIEM mapping

| Aegis field | Splunk | Elastic ECS |
|-------------|--------|-------------|
| `alert_id` | `event_id` | `event.id` |
| `severity` | `severity` | `event.severity` |
| `mitre.id` | `mitre_technique_id` | `threat.technique.id` |
| `entity.id` | `src_ip` or `host.name` | `source.ip` / `host.name` |
| `source_module` | `sourcetype` | `event.module` |

### Feedback loop

Analysts label false positives via `/feedback` to improve tuning:

```bash
curl -X POST .../feedback \
  -d '{"alert_id":"ALT-xxx","label":"false_positive","notes":"Legitimate scan"}'
```

## 6. Firewall / NAC Integration

When ready for live blocking (not simulation):

```env
SOAR_SIMULATION_MODE=false
AUTO_RESPONSE_ENABLED=false   # keep off globally; use per-request auto_respond
```

SOAR playbooks call `aegis/integrations/firewall.py`:

- `block_ip` — DROP rule in `AEGIS-BLOCK` chain
- `isolate_host` — restrict host to management VLAN
- `rate_limit_scanner` — rate-limit suspicious source

**Rollback:** each playbook records rule IDs for automatic rollback on failure.

## 7. Red Team / Purple Team

Import exercise findings:

```bash
curl -X POST .../ingest/red-team-finding \
  -d '{
    "finding_id": "RT-2026-001",
    "title": "Prompt injection via support form",
    "severity": "HIGH",
    "description": "Attacker injected override instructions...",
    "atlas_id": "AML.T0054"
  }'
```

ATLAS techniques from Project 10 are loaded into the knowledge base at startup.

## 8. Network Placement

| Deployment | Placement | Ports |
|------------|-----------|-------|
| Personal | Same host as services | 8080 |
| SMB | Dedicated VM, management VLAN | 8080, 514 (syslog) |
| Enterprise | HA pair behind load balancer | 8080, Redis 6379 |

**Firewall rules:**

- Inbound: 8080 from gateway subnets, SIEM, orchestration only
- Outbound: optional iptables/nftables on same host
- Deny: direct internet access to API in production

## 9. High Availability (Enterprise)

```env
DEPLOYMENT_PROFILE=enterprise
EVENT_BUS_BACKEND=redis
REDIS_URL=redis://redis-cluster:6379/0
```

Run multiple Aegis instances behind a load balancer. SQLite is per-instance; for shared state use external PostgreSQL (future) or central SIEM as source of truth for alerts.

## 10. Identity and Secrets

| Secret | Rotation | Storage |
|--------|----------|---------|
| `API_KEY` | 90 days | Vault / K8s Secret |
| `SQLITE_PATH` | N/A | Persistent volume |
| TLS cert | Annual | Ingress controller |

Never expose `/docs` in production (`ENVIRONMENT=production` disables OpenAPI UI).
