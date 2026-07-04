# Deployment Runbook

## Prerequisites

- Python 3.11+ or Docker 24+
- 512 MB RAM minimum (personal), 2 GB recommended (SMB)
- Persistent volume for `data/` (SQLite, ML model, audit ledger)

## Personal / Home Lab

### Option A: Native install

```bash
git clone <repo> && cd cybersec-04-jailbreak-threat-landscape
pip install -e ".[dev]"
cp config.example.env .env
# Edit API_KEY
aegis serve --port 8080
```

Verify:

```bash
curl http://localhost:8080/health
curl -H "X-API-Key: dev-key-change-in-production" http://localhost:8080/status
```

### Option B: Docker

```bash
export API_KEY=$(openssl rand -hex 32)
docker compose -f deploy/docker-compose.personal.yml up -d --build
docker compose -f deploy/docker-compose.personal.yml logs -f
```

Container hardening: non-root user, read-only rootfs, `no-new-privileges`, 512M memory cap.

## SMB Deployment

1. Dedicated Linux VM (Ubuntu 22.04 LTS)
2. Copy `.env` with production values:

```env
ENVIRONMENT=production
DEPLOYMENT_PROFILE=smb
API_KEY=<generated-32-byte-hex>
AUTO_RESPONSE_ENABLED=false
SOAR_SIMULATION_MODE=true
WATCHDOG_ENABLED=true
DATA_DIR=/var/lib/aegis
SQLITE_PATH=/var/lib/aegis/aegis.db
```

3. Systemd unit:

```ini
[Unit]
Description=Aegis Sentinel
After=network.target

[Service]
Type=simple
User=aegis
WorkingDirectory=/opt/aegis
EnvironmentFile=/opt/aegis/.env
ExecStart=/opt/aegis/.venv/bin/aegis serve
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

4. Reverse proxy (nginx) with TLS termination
5. Firewall: allow 443 from internal subnets only

## Enterprise Deployment

```env
DEPLOYMENT_PROFILE=enterprise
EVENT_BUS_BACKEND=redis
REDIS_URL=redis://redis.internal:6379/0
ENVIRONMENT=production
RATE_LIMIT_PER_MINUTE=600
```

- Deploy 2+ instances behind load balancer
- Central log shipping to SIEM
- API key per integration (use restricted keys per service)
- Enable live SOAR only after firewall integration testing

## Pre-Production Checklist

- [ ] `API_KEY` set to cryptographically random value
- [ ] `ENVIRONMENT=production`
- [ ] `AUTO_RESPONSE_ENABLED=false` (enable per-integration after testing)
- [ ] `SOAR_SIMULATION_MODE=true` until firewall validated
- [ ] Persistent backup of `data/` directory
- [ ] Health check monitored (`GET /health`)
- [ ] Audit chain verified (`status.audit_chain.valid == true`)
- [ ] `pytest tests/ -v` passes in CI

## Upgrade Procedure

```bash
git pull origin main
pip install -e ".[dev]"
pytest tests/ -v
systemctl restart aegis
curl -H "X-API-Key: $KEY" http://localhost:8080/status
```

## Rollback

```bash
git checkout v1.0.0-beta
pip install -e ".[dev]"
systemctl restart aegis
```

## Backup

Daily cron:

```bash
sqlite3 /var/lib/aegis/aegis.db ".backup /backup/aegis-$(date +%F).db"
tar czf /backup/aegis-kb-$(date +%F).tar.gz knowledge-base/
```

## Monitoring

| Check | Endpoint / Command | Alert if |
|-------|-------------------|----------|
| Liveness | `GET /health` | non-200 |
| Audit integrity | `GET /status` → `audit_chain.valid` | false |
| Module health | `GET /modules` | any `healthy: false` |
| Disk | `df /var/lib/aegis` | >85% |
