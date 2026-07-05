# Aegis Sentinel — Product One-Pager

**Unified cybersecurity for company networks, endpoints, and AI workloads.**

---

## What It Does

Aegis Sentinel ingests security telemetry from your network, servers, containers, and LLM applications. It detects threats in real time using IOCs, heuristics, and offline machine learning, correlates alerts into incidents, and optionally executes automated response playbooks — with a tamper-evident audit trail for compliance.

## Key Capabilities

- **LLM & AI security** — jailbreak, prompt injection, agent tool poisoning, RAG corpus attacks, VLM abuse
- **Network IDS** — port scans, DNS C2, flow anomalies
- **Endpoint protection** — brute force, malware indicators, file hash IOCs
- **Runtime security** — Falco/container escape detection
- **Adversarial ML** — evasion detection on feature streams
- **Red team integration** — MITRE ATLAS finding import

## How It Fits Your Network

```
[Sensors] → [Aegis API :8080] → [SIEM / SOC]
                  ↓
            [Firewall SOAR]
```

Integrates via REST API, syslog, and standard log forwarders. No dependency on external generative AI for detection.

## Safety Defaults

- Auto-response **disabled** by default
- SOAR **simulation mode** until firewall integration is validated
- API key authentication on all sensitive endpoints
- SHA-256 hash-chained audit ledger

## Deployment

| Profile | RAM | Setup time |
|---------|-----|------------|
| Personal (Docker) | 512 MB | 5 minutes |
| SMB (VM + systemd) | 2 GB | 1 hour |
| Enterprise (HA + Redis) | 4+ GB | 1 day |

## Proof Points

- 9 integrated security modules (Projects 04–10 + network + host)
- 44+ threat techniques in knowledge base
- 32 automated tests passing
- Sub-20ms tiered detection pipeline

## Contact

Repository: `cybersec-04-jailbreak-threat-landscape`  
Version: **1.0.0-beta**  
Docs: `/docs/ARCHITECTURE.md`, `/docs/NETWORK_INTEGRATION.md`

---

*Print this page double-sided for trade show handouts.*
