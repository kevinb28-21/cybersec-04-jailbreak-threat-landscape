# Product Release & Distribution Plan

**Product:** Aegis Sentinel  
**Current version:** v1.0.0-beta  
**Target GA:** v1.0.0 (after 5 design partners + 90 days stable)

---

## 1. Release Maturity Model

| Stage | Version | Criteria | Status |
|-------|---------|----------|--------|
| **Alpha** | 0.x | Internal modules, no unified API | ✅ Complete |
| **Beta** | 1.0.0-beta | 9 modules, API, 32 tests, docs | ✅ **Current** |
| **RC** | 1.0.0-rc1 | 5 design partners, 30 days no P0 bugs | ⬜ Next |
| **GA** | 1.0.0 | Billing, license enforcement, SLA | ⬜ Target |
| **Enterprise** | 1.1+ | SSO, RBAC, HA, marketplace | ⬜ Year 2 |

---

## 2. Beta → GA Gate Criteria

All must pass before removing “beta” label:

| Gate | Requirement | Owner |
|------|-------------|-------|
| Quality | 32+ pytest pass; UAT 28/28; 0 open P0/P1 bugs | Engineering |
| Customers | 5 paid design partners active 30+ days | Founder |
| Docs | Master plan + runbooks complete | Product |
| Security | Third-party pen test OR public bug bounty | Security |
| Ops | 99.5% uptime on demo instance (30 days) | Engineering |
| Legal | EULA, privacy policy, DPA template | Legal/founder |
| Billing | Stripe integration + tier enforcement | Engineering |
| Support | Documented SLA + support email | Ops |

---

## 3. Release Channels

### Channel A — Self-Hosted (Primary)

**Target:** Technical buyers, data sovereignty, EU GDPR

```
GitHub release → Docker Hub image → docker compose up
```

| Artifact | Location | Update cadence |
|----------|----------|----------------|
| Source | GitHub (`kevinb28-21/cybersec-04-jailbreak-threat-landscape`) | Every sprint |
| Docker image | `ghcr.io/<org>/aegis-sentinel:<tag>` | Per release tag |
| Helm chart (future) | `deploy/helm/` | v1.1 |

**Install path:**

```bash
curl -fsSL https://get.aegis-sentinel.io/install.sh | bash  # future
# Today:
git clone ... && pip install -e ".[dev]" && aegis serve
```

### Channel B — Managed Cloud (Year 2)

**Target:** Non-technical SMB buyers

| Tier | Hosting | Isolation |
|------|---------|-----------|
| Starter | Multi-tenant SaaS | Namespace per customer |
| Professional | Single-tenant VPC | Dedicated instance |
| Enterprise | Customer VPC / on-prem | Air-gap option |

**Build after:** 20 self-hosted customers validate feature set.

### Channel C — Marketplace

| Marketplace | When | Purpose |
|-------------|------|---------|
| AWS Marketplace | Year 2 | Enterprise procurement ([HiddenLayer lists here at $5M list](https://aws.amazon.com/marketplace/pp/prodview-2haypjrayfxgw)) |
| Pax8 / Sherweb | Year 2 | MSP distribution |
| Docker Hub Verified | v1.0 GA | Discoverability |

### Channel D — OEM / Embed

**Target:** LLM gateway vendors, MSP platforms

- License `aisec-guard` module as SDK
- White-label API: `detect()` function
- Revenue share 20–30%

**When:** Inbound OEM interest or 100+ customers.

---

## 4. Versioning & Release Cadence

Follow [Semantic Versioning](https://semver.org/):

| Change type | Version bump | Example |
|-------------|--------------|---------|
| Breaking API change | MAJOR | 2.0.0 |
| New module / endpoint | MINOR | 1.1.0 |
| Bug fix, detection rule | PATCH | 1.0.1 |

**Cadence:**
- Patch: as needed (security fixes within 24h)
- Minor: monthly during Year 1
- Major: annual or breaking change only

**Release process:**

```
1. Feature branch → PR → CI (pytest + lint)
2. Merge to main
3. Tag vX.Y.Z + CHANGELOG entry
4. Build Docker image
5. GitHub Release notes
6. Notify design partners / mailing list
7. Update docs/
```

---

## 5. Distribution by Customer Segment

| Segment | Primary channel | Install method | Buyer journey |
|---------|-----------------|----------------|---------------|
| Developer / hobbyist | GitHub + Community tier | Docker self-serve | README → Docker → upgrade |
| Startup (Series A–C) | Founder sales + GitHub | Docker + API key | Demo → design partner → annual |
| SMB (20–200) | Founder sales → MSP | Docker or managed | Compliance trigger → demo → Professional |
| Enterprise | Direct + AWS Marketplace | On-prem / VPC | RFP → POC → Enterprise quote |
| MSP | Partner portal | Multi-tenant deploy | Wholesale → white-label → end clients |

---

## 6. Packaging for Distribution

### What ships in each release artifact

```
aegis-sentinel-v1.0.0/
├── aegis/                    # Platform source
├── knowledge-base/           # Threat intel (versioned with release)
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.personal.yml
│   └── docker-compose.enterprise.yml  # future
├── docs/                     # Full documentation set
├── scripts/
│   ├── uat.sh
│   └── clone-cyber-projects.sh
├── config.example.env
├── CHANGELOG.md
└── LICENSE                   # Proprietary or open-core split
```

### Open-core split (recommended for PLG)

| Component | License | Tier |
|-----------|---------|------|
| aisec-guard, net-sentinel, host-shield | Apache 2.0 or source-available | Community |
| agent-guard, rag-guard, vlm-guard, runtime-guard, adversarial-ml, red-team-engine | Proprietary | Starter+ |
| SOAR live playbooks | Proprietary | Professional+ |
| Audit chain export for compliance | Proprietary | Professional+ |

---

## 7. Launch Sequence (Recommended)

### Launch 1 — Private Beta (Now)

- **Audience:** 5–10 design partners only
- **Channel:** Direct outreach
- **Version:** v1.0.0-beta
- **Goal:** Product feedback, case studies

### Launch 2 — Public Beta (Month 3)

- **Audience:** GitHub public, Show HN, communities
- **Channel:** Product-led + content
- **Version:** v1.0.0-rc1
- **Goal:** 500 Docker pulls, 50 demo requests

### Launch 3 — General Availability (Month 6–9)

- **Audience:** Paid tiers open, pricing page live
- **Channel:** Full GTM (outbound + inbound + first MSP)
- **Version:** v1.0.0
- **Goal:** $15K+ MRR

### Launch 4 — Enterprise & Marketplace (Month 12–18)

- **Audience:** Enterprise + AWS Marketplace
- **Version:** v1.1.0
- **Goal:** First $60K+ ACV deal

---

## 8. CI/CD & Release Infrastructure

| Component | Tool | Status |
|-----------|------|--------|
| Tests | pytest (32 tests) | ✅ |
| UAT | `scripts/uat.sh` | ✅ |
| CI | GitHub Actions | ⬜ Add workflow |
| Docker build | GitHub Actions → GHCR | ⬜ |
| Staging | Always-on demo instance | ⬜ |
| Production | Customer self-hosted | ✅ model |
| Feature flags | `aegis/config.py` settings | ✅ partial |
| License enforcement | API key + tier flags | ⬜ GA blocker |

**Recommended GitHub Actions workflow (to build):**

```yaml
# .github/workflows/release.yml
on:
  push:
    tags: ['v*']
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e ".[dev]" && pytest tests/ -v
  docker:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - run: docker build -f deploy/Dockerfile -t ghcr.io/org/aegis:${{ github.ref_name }} .
```

---

## 9. Support & SLA by Release Tier

| Tier | Support channel | SLA | Included |
|------|-----------------|-----|----------|
| Community | GitHub issues | Best effort | — |
| Starter | Email | 48h | Business hours |
| Professional | Email + chat | 24h | Business hours |
| Business | Named contact | 4h | Extended hours |
| Enterprise | 24/7 option | 1h | Dedicated |

---

## 10. Rollback & Incident Process

| Severity | Response | Communication |
|----------|----------|---------------|
| P0 — detection bypass in wild | Patch within 24h; emergency release | Email all customers |
| P1 — API down / data loss | Fix within 4h | Status page |
| P2 — false positive spike | Rule update within 72h | Release notes |
| P3 — docs / UX | Next minor release | Changelog |

**Rollback:** Customers on Docker pin to previous tag:

```bash
docker pull ghcr.io/org/aegis:v1.0.0-beta
```

---

## 11. Legal & Compliance for Distribution

| Document | Required for | Status |
|----------|--------------|--------|
| EULA | All paid tiers | ⬜ Create |
| Privacy policy | SaaS / website | ⬜ Create |
| DPA (GDPR) | EU customers | ⬜ Create |
| Security whitepaper | Enterprise sales | ⬜ Use ARCHITECTURE.md as base |
| SOC 2 Type I | Enterprise Year 2 | ⬜ Plan |

---

## 12. Success Metrics by Release Stage

| Stage | Metric | Target |
|-------|--------|--------|
| Private beta | Design partners | 5 |
| Public beta | GitHub stars | 200+ |
| Public beta | Docker pulls/month | 500+ |
| GA | Paying customers | 20 |
| GA | MRR | $27K+ |
| Enterprise launch | $60K+ ACV deals | 2 |

See `GO_TO_MARKET.md` for customer acquisition tactics and `PRICING_STRATEGY.md` for revenue targets.
