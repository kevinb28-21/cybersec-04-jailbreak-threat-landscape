# User Acceptance Test Report

**Product:** Aegis Sentinel v1.0.0-beta  
**Date:** 2026-07-04  
**Environment:** Linux, Python 3.12, API on `127.0.0.1:8080`  
**Tester role:** QA engineer + end-user simulation

## Summary

| Suite | Tests | Pass | Fail |
|-------|-------|------|------|
| pytest (automated) | 32 | 32 | 0 |
| UAT script (live API + CLI) | 28 | 28 | 0 |
| **Total** | **60** | **60** | **0** |

**Result: PASS** — all use cases verified.

## QA Audit — Bugs Found and Fixed

| ID | Severity | Issue | Fix |
|----|----------|-------|-----|
| C1 | Critical | Alert dedup suppressed distinct threats on same entity | Dedup key now includes MITRE, kb_refs, description hash |
| C2 | Critical | Correlation over-merged unrelated same-module alerts | Requires MITRE/kb overlap or adjacent kill-chain stages |
| C3 | Critical | `auto_response_enabled` did not force tier-3 playbooks | Pass `force=True` to SOAR when auto-respond enabled |
| C4 | Critical | Red-team ATLAS import was no-op | `import_atlas_techniques()` wired to knowledge base |
| C5 | Critical | `reload()` missing from knowledge base (startup break) | Restored `reload()` method |
| H1 | High | `isolate_host` rollback IDs mismatched firewall | Consistent rule IDs in firewall integration |
| H2 | High | Duplicate iptables INPUT jumps | Chain existence check before insert |
| H4 | High | `verify_block` always true in simulation | Checks internal block state |
| H5 | High | Feedback only searched last 500 alerts | Uses `correlator.alert_exists()` |
| H6 | High | No red-team ingest API | Added `POST /ingest/red-team-finding` |
| M1 | Medium | `_redact_alert` mutated stored dict | Returns copy |
| M2 | Medium | Empty prompt/image accepted | `min_length=1` validation |
| M3 | Medium | Tier-0 dedup permanent | 60s TTL-based dedup |
| M4 | Medium | CLI `test-scan` showed only last result | Aggregate `total_alerts` in output |

## UAT Coverage

### API Endpoints

| Endpoint | Method | Result |
|----------|--------|--------|
| `/health` | GET | PASS |
| `/status` | GET | PASS (auth required) |
| `/knowledge/stats` | GET | PASS |
| `/playbooks` | GET | PASS |
| `/ingest/prompt` | POST | PASS |
| `/ingest/flow` | POST | PASS |
| `/ingest/log` | POST | PASS |
| `/ingest/dns` | POST | PASS |
| `/ingest/hash` | POST | PASS |
| `/ingest/agent-tool` | POST | PASS |
| `/ingest/rag-chunk` | POST | PASS |
| `/ingest/runtime` | POST | PASS |
| `/ingest/ml-features` | POST | PASS |
| `/ingest/red-team-finding` | POST | PASS |
| `/alerts` | GET | PASS |
| `/incidents` | GET | PASS |
| `/feedback` | POST | PASS |
| `/alerts/{id}/status` | PATCH | PASS |
| Empty prompt validation | POST | PASS (422) |
| Invalid feedback alert | POST | PASS (404) |

### CLI Commands

| Command | Result |
|---------|--------|
| `aegis status` | PASS |
| `aegis test-prompt` | PASS |
| `aegis test-scan` | PASS |

### Security Modules Exercised

- aisec-guard (LLM jailbreak)
- net-sentinel (port scan, DNS IOC)
- host-shield (brute force log)
- agent-guard (tool poisoning)
- rag-guard (corpus injection)
- runtime-guard (Falco alert)
- adversarial-ml (feature evasion)
- red-team-engine (finding ingest)

## Reproduction

```bash
# Automated tests
pytest tests/ -v

# Live UAT (start server first)
aegis serve --port 8080
./scripts/uat.sh
```

## Sign-Off

Platform is ready for beta deployment with simulation-mode SOAR. Enable live firewall response only after staging validation per `docs/DEPLOYMENT_RUNBOOK.md`.
