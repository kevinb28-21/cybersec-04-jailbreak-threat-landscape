# API Reference

Base URL: `http://<host>:8080`

Authentication: `X-API-Key: <API_KEY>` on all endpoints except `/health`.

Rate limit: 120 requests/minute per client IP on ingest endpoints.

---

## Health

### `GET /health`

No authentication required.

```json
{"status": "ok", "version": "1.0.0-beta", "profile": "personal"}
```

---

## Platform Status

### `GET /status`

Returns module health, knowledge base stats, audit chain validity, playbook list.

### `GET /modules`

Per-module health metrics.

---

## Ingest Endpoints

All ingest endpoints accept optional `"auto_respond": true` to trigger SOAR playbooks for that request.

### `POST /ingest/prompt`

LLM prompt analysis (Project 04 — aisec-guard).

```json
{
  "prompt": "string (1–32000 chars, required)",
  "entity_id": "llm-gateway",
  "session_id": "default",
  "auto_respond": false
}
```

### `POST /ingest/flow`

Network flow (net-sentinel).

```json
{
  "src_ip": "203.0.113.50",
  "dst_port": 22,
  "protocol": "tcp",
  "bytes_sent": 64,
  "auto_respond": false
}
```

### `POST /ingest/dns`

DNS query analysis.

```json
{"src_ip": "10.0.0.5", "domain": "evil-c2.example.com", "auto_respond": false}
```

### `POST /ingest/log`

Host log line (host-shield).

```json
{"host_id": "workstation-01", "log_line": "Failed password for root", "auto_respond": false}
```

### `POST /ingest/hash`

File hash IOC check.

```json
{"host_id": "ws-01", "file_hash": "abc123...", "file_path": "/tmp/file.exe", "auto_respond": false}
```

### `POST /ingest/agent-tool`

AI agent tool output (Project 05).

```json
{
  "agent_id": "agent-1",
  "tool_name": "web_search",
  "output": "tool result text",
  "session_id": "",
  "auto_respond": false
}
```

### `POST /ingest/rag-chunk`

RAG retrieved chunk (Project 06).

```json
{
  "collection": "kb",
  "source": "doc.pdf",
  "chunk": "retrieved text",
  "trust_level": 1,
  "auto_respond": false
}
```

### `POST /ingest/image`

VLM image analysis (Project 07).

```json
{"image_path": "/path/to/image.png", "auto_respond": false}
```

### `POST /ingest/runtime`

Falco/runtime alert (Project 08).

```json
{
  "rule": "Container Accessing Docker Socket",
  "output": "process=python3 file=/var/run/docker.sock",
  "container": "llm-api",
  "priority": "CRITICAL",
  "auto_respond": false
}
```

### `POST /ingest/ml-features`

Adversarial ML features (Project 09).

```json
{
  "source_ip": "10.0.0.1",
  "features": [0.1, 0.2, 0.3],
  "ml_score": 0.8,
  "auto_respond": false
}
```

### `POST /ingest/red-team-finding`

Red team exercise finding (Project 10).

```json
{
  "finding_id": "RT-001",
  "title": "Prompt injection finding",
  "severity": "HIGH",
  "description": "Detailed finding text",
  "atlas_id": "AML.T0054",
  "auto_respond": false
}
```

---

## Ingest Response Schema

```json
{
  "event_id": "uuid",
  "confidence": 0.85,
  "severity": "high",
  "alerts": ["ALT-..."],
  "incidents": ["INC-..."],
  "remediations": [],
  "auto_respond": false,
  "suppressed_alerts": 0,
  "threat_detected": true
}
```

---

## Alerts & Incidents

### `GET /alerts?limit=50`

Returns recent alerts. Descriptions >120 chars are redacted in API output (copy-safe; does not mutate stored data).

### `GET /incidents?limit=50`

Correlated incident groups.

### `PATCH /alerts/{alert_id}/status?status=acknowledged`

Status values: `open`, `investigating`, `contained`, `resolved`, `false_positive`.

---

## Knowledge Base

### `GET /knowledge/techniques?q=&category=&severity=`

Search threat techniques.

### `GET /knowledge/stats`

Technique counts by source and severity, IOC count.

---

## SOAR

### `GET /playbooks`

List available playbook IDs.

---

## Feedback

### `POST /feedback`

```json
{"alert_id": "ALT-...", "label": "true_positive", "notes": "optional"}
```

Label must be `true_positive` or `false_positive`. Alert must exist (not limited to last 500).

---

## Error Codes

| Code | Meaning |
|------|---------|
| 401 | Missing or invalid API key |
| 404 | Alert not found |
| 422 | Validation error (empty prompt, etc.) |
| 429 | Rate limit exceeded |
| 500 | Module unavailable |
