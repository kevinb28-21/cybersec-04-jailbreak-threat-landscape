# Pricing Strategy — Aegis Sentinel

**Version:** 1.0  
**Date:** July 2026  
**Basis:** Competitive benchmarking against LLM security, SOAR, and SMB endpoint pricing (see `MARKET_RESEARCH.md`)

---

## Pricing Philosophy

1. **Transparent tiers** — SMB buyers reject opaque “contact sales” for first purchase (unlike Lakera post-acquisition).
2. **Land with AI, expand to full platform** — Lead with LLM/agent modules; upsell network + SOAR.
3. **Self-hosted default** — No per-prompt cloud tax; charge for platform value (modules, events, support).
4. **Simulation-safe SOAR included** — Differentiate from $30K+ standalone SOAR; charge more for live response + SLA.
5. **Compliance packaging** — EU AI Act / SOC 2 audit bundle as premium add-on.

---

## Competitive Price Anchors (2026)

| Category | Low | Mid | High | Source |
|----------|-----|-----|------|--------|
| LLM security API | Free tier / $99/mo (historical Lakera) | $25K+/yr enterprise | $100K+/yr | RuneSec, Toosio |
| AI security platform | $30K/yr | $80K/yr | $150K+/yr | CostBench (HiddenLayer, Protect AI) |
| SOAR standalone | $24K/yr | $40K–$150K/yr | $300K+/yr | Ciphers, Zendikt |
| SMB endpoint security | $5/endpoint/mo | $15/endpoint/mo | $35/endpoint/mo | Market Intelo |
| Managed SOC (MSSP) | $11/endpoint/mo | — | $15/endpoint/mo | UnderDefense |
| Early-stage security services | $7.5K | $15K | — | Lorikeet playbook (project/SOW) |

**Aegis target zone:** **Below enterprise AI security ($25K+)** but **above pure open-source** — capturing value of unified platform + SOAR + self-hosting.

---

## Recommended Pricing Tiers

### Tier 0 — Community (Free)

**Purpose:** Product-led growth, developer adoption, GitHub stars, word of mouth.

| Included | Limits |
|----------|--------|
| Self-hosted Docker deploy | 1 instance |
| Modules: aisec-guard, net-sentinel, host-shield | 3 modules only |
| Ingest events | 10,000 / month |
| SOAR | Simulation mode only |
| Support | Community (GitHub issues) |
| Audit chain | Yes |

**Price:** $0

**Conversion trigger:** Hit event limit, need agent-guard/rag-guard/runtime, or want email support.

---

### Tier 1 — Starter

**Purpose:** Solo founders, small teams shipping an LLM feature.

| Included | Limits |
|----------|--------|
| All 9 modules | ✓ |
| Ingest events | 100,000 / month |
| API keys | 3 |
| SOAR | Simulation mode |
| Knowledge base updates | Quarterly |
| Support | Email, 48h SLA |

**Price:** **$499/month** ($4,990/year if prepaid — 2 months free)

**Comparable value:** Lakera-like LLM guard + basic monitoring at fraction of enterprise AI security cost.

---

### Tier 2 — Professional (Primary SMB tier)

**Purpose:** Growth-stage companies (20–200 employees) with LLM + infrastructure to protect.

| Included | Limits |
|----------|--------|
| All 9 modules | ✓ |
| Ingest events | 500,000 / month |
| API keys | 10 |
| SOAR | Simulation + 1 live playbook (e.g. block_ip) |
| SIEM export | Webhook + JSON polling |
| EU AI Act compliance report | Monthly PDF |
| Support | Email + chat, 24h SLA |

**Price:** **$1,499/month** ($14,990/year prepaid)

**Per-endpoint equivalent:** For 100-employee company ≈ **$15/employee/month** — aligned with managed SOC low end but self-hosted.

---

### Tier 3 — Business

**Purpose:** Mid-market (200–500 employees), MSP single-tenant, regulated industries.

| Included | Limits |
|----------|--------|
| All modules + HA profile (Redis bus) | ✓ |
| Ingest events | 2,000,000 / month |
| SOAR | Full live playbooks |
| Dedicated onboarding | 8 hours |
| Custom IOC feeds | ✓ |
| Red-team import + purple team dashboard | ✓ |
| Support | 4h SLA, named contact |

**Price:** **$3,999/month** ($39,990/year prepaid)

---

### Tier 4 — Enterprise

**Purpose:** 500+ employees, multi-site, custom compliance.

| Included | Limits |
|----------|--------|
| Unlimited events (fair use) | ✓ |
| Multi-instance / HA | ✓ |
| SSO, RBAC | ✓ |
| Custom playbooks | ✓ |
| On-prem + air-gap support | ✓ |
| Support | 1h SLA, 24/7 option |

**Price:** **From $60,000/year** (custom quote)

**Floor rationale:** Still below HiddenLayer/Lakera enterprise ($25K–$150K) while capturing full-platform value.

---

## Add-Ons

| Add-on | Price | Notes |
|--------|-------|-------|
| Extra 500K ingest events | $200/mo | Usage-based expansion |
| Live SOAR pack (Professional) | $500/mo | Unlocks all live playbooks |
| EU AI Act audit package | $2,500 one-time + $300/mo | Article 15 documentation + quarterly review |
| Purple team exercise (Project 10) | $5,000–$15,000 | Professional services; Lorikeet-style SOW |
| Priority support upgrade | $500/mo | 4h → 1h SLA |
| MSP white-label | 30% wholesale discount | Min 10 end-customer seats |

---

## MSP / Channel Pricing

MSPs are the **primary scale channel** for SMB (see Huntress/RiffOn case study — SMBs outsource IT to MSPs).

| Model | Price to MSP | MSP suggested retail | MSP margin |
|-------|--------------|----------------------|------------|
| Per-endpoint bundle (Aegis + monitoring) | $8/endpoint/mo | $18–25/endpoint/mo | 55–68% |
| Per-site flat (≤50 employees) | $299/mo wholesale | $499–799/mo | 40–63% |

**Requirements before MSP program:** 5+ direct customers, documented deployment runbook, 3 reference accounts (see `GO_TO_MARKET.md`).

---

## Revenue Model & Projections

### Unit economics (target at scale)

| Metric | Target | Notes |
|--------|--------|-------|
| Gross margin | 85%+ | Self-hosted software; services optional |
| CAC (founder-led) | ~$0–$500 | Founder time is sunk cost early |
| CAC (scaled) | <$5,000 | Content + 1 AE |
| LTV (Professional tier) | $45K+ | 3-year retention at $1,499/mo |
| LTV:CAC | >3:1 | Required before heavy marketing spend |
| Net revenue retention | 110%+ | Upsell events, SOAR, enterprise |

### Three-year revenue scenarios

Assumptions: mix of Starter (20%), Professional (55%), Business (20%), Enterprise (5%) by Year 3.

#### Conservative

| Year | New customers | Total customers | Blended ARPU/mo | ARR |
|------|---------------|-----------------|-----------------|-----|
| 1 | 12 | 12 | $1,200 | **$173K** |
| 2 | 25 | 35 | $1,400 | **$588K** |
| 3 | 40 | 70 | $1,600 | **$1.34M** |

#### Base case

| Year | New customers | Total customers | Blended ARPU/mo | ARR |
|------|---------------|-----------------|-----------------|-----|
| 1 | 20 | 20 | $1,350 | **$324K** |
| 2 | 45 | 62 | $1,550 | **$1.15M** |
| 3 | 70 | 125 | $1,750 | **$2.63M** |

#### Optimistic (MSP channel active Year 2)

| Year | Direct + MSP end customers | Blended ARPU/mo | ARR |
|------|---------------------------|-----------------|-----|
| 1 | 25 | $1,400 | **$420K** |
| 2 | 90 | $1,500 | **$1.62M** |
| 3 | 220 | $1,650 | **$4.36M** |

### How much money this could make (founder summary)

| Timeframe | Conservative | Base | Optimistic |
|-----------|--------------|------|------------|
| Year 1 | ~$175K ARR | ~$325K ARR | ~$420K ARR |
| Year 3 | ~$1.3M ARR | ~$2.6M ARR | ~$4.4M ARR |
| Year 5 (if 20% YoY growth from Y3 base) | ~$2.0M | ~$4.0M | ~$6.7M |

**At SaaS multiples of 8–12× ARR** (cybersecurity premium), a $2.6M ARR business (base Year 3) implies **$21M–$31M** potential valuation — consistent with strategic acquirer interest in AI security (Lakera ~$187M at earlier stage with strong tech).

*These are models, not guarantees. Validate with 10 paying design partners in first 90 days.*

---

## Pricing Experiments (First 90 Days)

| Experiment | Price point | Goal |
|------------|-------------|------|
| Design partner SOW | $7,500–$15,000 one-time | 90-day pilot + feedback; Lorikeet-validated range |
| Starter annual prepay | $4,990 vs $5,990 | Measure price sensitivity |
| Professional | $999 vs $1,499 vs $1,999 | Van Westendorp survey with 20 ICP interviews |
| Event overage | $150 vs $200 per 500K | Usage expansion revenue |

**Do not discount below 20%** in Year 1 — trains market to wait for deals.

---

## Billing & Packaging Mechanics

| Element | Implementation |
|---------|----------------|
| License key | Per-tier feature flags in `aegis/config.py` (future) |
| Usage metering | Count ingest API calls; expose in `/status` |
| Payment | Stripe Billing for SaaS; invoice for Enterprise |
| Marketplace | List on AWS Marketplace Year 2 (HiddenLayer pattern for enterprise discovery) |
| Open core | Community tier on GitHub; paid tiers for modules 05–10 + SOAR live |

---

## Pricing Page Copy (External-facing)

**Headline:** Unified AI + network security from $499/month. No per-prompt fees.

**Sub:** Self-hosted. MITRE ATLAS + ATT&CK. SOAR included. EU AI Act ready.

**CTA ladder:**
1. Start free (Community Docker)
2. Book 30-min demo
3. Design partner program ($7.5K — 90-day pilot)

See `GO_TO_MARKET.md` for how to sell each tier with zero existing customers.
