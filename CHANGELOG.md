# Aegis Sentinel v1.0.0-beta

First beta release of the unified cybersecurity platform integrating all numbered cyber projects (04–10).

## Integrated projects

- **04** — LLM jailbreak threat landscape → `aisec-guard`
- **05** — AI agent security testing lab → `agent-guard`
- **06** — RAG poisoning attack simulation → `rag-guard`
- **07** — Steganographic prompt injection → `vlm-guard`
- **08** — LLM container escape testing → `runtime-guard`
- **09** — Adversarial attack on AI-IDS → `adversarial-ml`
- **10** — AI red team full exercise → `red-team-engine`

## Highlights

- 9 security modules under one orchestration layer
- 44+ techniques in unified knowledge base
- API auth, rate limiting, SOAR with iptables integration
- Syslog collector + self-healing watchdog
- 26 automated tests

## Install

```bash
pip install -e ".[dev]"
cp config.example.env .env
aegis serve
```
