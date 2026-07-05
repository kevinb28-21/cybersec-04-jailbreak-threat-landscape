# Go-To-Market Strategy — Zero Customer Base

**Product:** Aegis Sentinel v1.0.0-beta  
**Starting point:** No customers, no brand, beta product  
**Goal:** First 25 paying customers within 12 months; $300K+ ARR by end of Year 1 (base case)

This plan synthesizes founder-led security sales best practices from [Lorikeet Security](https://lorikeetsecurity.com/blog/founder-led-security-sales-playbook), [Cyber Building Blocks GTM stages](https://cyberbuildingblocks.substack.com/p/the-8-gtm-stages-for-building-a-cybersecurity), and [Allure Security’s proof-point strategy](https://www.frontlines.io/7-go-to-market-lessons-from-building-a-cybersecurity-company-in-a-market-that-doesnt-believe-solutions-exist/).

---

## 1. Ideal Customer Profile (ICP) — Start Here

### Primary ICP (Months 1–12)

**“AI-forward growth company”**

| Attribute | Target |
|-----------|--------|
| Company size | 20–200 employees |
| Stage | Series A–C startup OR profitable SMB |
| Geography | US, UK, EU (English-first) |
| Tech signal | Ships LLM feature (chatbot, copilot, RAG, or agents) |
| Compliance trigger | SOC 2 in progress, EU AI Act exposure, cyber insurance renewal |
| Buyer | CTO, VP Engineering, Head of Security (if exists) |
| Budget | $500–$3,000/month discretionary security |
| IT model | 0–2 person IT; no 24/7 SOC |

**Why this ICP first:**
- Fast decisions (no 6-month RFP) — [Lorikeet playbook](https://lorikeetsecurity.com/blog/founder-led-security-sales-playbook)
- Compliance-driven urgency (SOC 2, EU AI Act Aug 2026)
- Forgiving of beta polish if detection works
- CAC ≈ $0 with founder-led sales

### Secondary ICP (Months 6–18)

| Attribute | Target |
|-----------|--------|
| MSP / MSSP | 50–500 end clients; wants AI security SKU |
| Vertical | Fintech, healthtech, legal tech (AI + regulated) |

### Anti-ICP (do not pursue yet)

- Enterprise 5,000+ employees (long procurement)
- Companies with no AI in production (no urgency)
- Pure government/FedRAMP (certification cost too high pre-revenue)

---

## 2. Positioning Statement

**For** engineering-led companies deploying LLMs and agents in production  
**Who** cannot afford separate LLM firewalls, SOAR, and network IDS  
**Aegis Sentinel is** a unified, self-hosted security platform  
**That** detects jailbreaks, agent poisoning, network attacks, and runtime threats in one pipeline with automated response and audit logging  
**Unlike** Lakera or HiddenLayer (AI-only, enterprise pricing) or Cortex XSOAR (SOC-only, $50K+)  
**We** deliver MITRE ATLAS + ATT&CK coverage across AI and infrastructure at SMB-accessible pricing.

---

## 3. Phase 0 — Foundation (Weeks 1–4)

Before outbound sales, complete:

| Task | Owner | Done when |
|------|-------|-----------|
| Public GitHub repo polished | Engineering | README, docs/, demo video |
| Landing page with clear ICP | Founder | 1-page site: problem → demo → pricing → CTA |
| Design partner offer documented | Founder | $7.5K–$15K / 90-day pilot SOW template |
| Demo environment always-on | Engineering | Docker + `scripts/uat.sh` green |
| 3-minute demo video | Founder | Loom: jailbreak → scan → status |
| LinkedIn founder narrative | Founder | 2 posts/week on AI security incidents |
| Calendly “Book demo” | Founder | 30-min slots |

**Budget:** $0–$2K (domain, landing page builder, Loom Pro optional)

---

## 4. Phase 1 — Design Partners (Months 1–3)

**Target:** 5–10 design partners at **$7,500–$15,000** for 90-day pilot (not free — paid validates willingness-to-pay per Lorikeet guidance).

### Offer structure

```
Design Partner Program — Aegis Sentinel
────────────────────────────────────────
Price: $7,500 (startup) / $15,000 (50–200 employees)
Duration: 90 days
Includes:
  • Full platform deploy (all 9 modules)
  • Weekly 30-min check-in with founder
  • Custom IOC + playbook tuning for your stack
  • EU AI Act / SOC 2 evidence pack (audit chain exports)
  • Logo + case study rights (optional discount)
Outcome: Go/no-go on annual subscription at 20% partner discount
```

### Where to find design partners

| Channel | Tactic | Volume |
|---------|--------|--------|
| **Personal network** | Email 50 founders/CTOs you know | 50 outreach → 5 meetings |
| **LinkedIn outbound** | Comment on AI security breach posts; DM CTOs | 100 DMs/month |
| **Hacker News / Reddit** | “Show HN: self-hosted LLM + network security platform” | 1 launch post |
| **AI engineering communities** | Latent Space Discord, MLOps Community, local meetups | 2 events/month |
| **Accelerators** | YC, Techstars portfolio companies deploying AI | Partner with 1 accelerator for workshop |
| **Compliance consultants** | SOC 2 auditors who need AI security control | 5 consultant partnerships |

### Outreach template

```
Subject: LLM security + network IDS in one self-hosted platform?

Hi [Name],

I saw [company] is shipping [AI feature]. We're building Aegis Sentinel —
unified detection for prompt injection, agent tool poisoning, port scans,
and container runtime threats — with MITRE ATLAS mapping and SOAR playbooks.

Looking for 5 design partners ($7.5K / 90-day pilot). Self-hosted Docker,
no per-prompt cloud fees.

Worth a 20-min call? [Calendly link]

[Founder name]
```

### Success metrics (Month 3)

| Metric | Target |
|--------|--------|
| Design partner signed | 5+ |
| Pilot revenue | $37K–$75K |
| Case studies | 2 written |
| NPS from partners | ≥ 40 |

---

## 5. Phase 2 — Founder-Led Sales (Months 4–9)

**Target:** Convert 50% of design partners + add 10 new customers → **15–20 total paying**.

### Sales motion (repeatable)

```
1. Discovery call (30 min)
   → Confirm ICP: LLM in prod? Compliance deadline? Current stack?

2. Technical demo (45 min)
   → Live: ingest/prompt jailbreak + ingest/flow scan + /status audit chain
   → Use docs/DEMO_PRESENTATION_PLAN.md

3. Scoping doc (same day)
   → Modules needed, event volume estimate, integration points

4. Proposal (48 hours)
   → Tier recommendation (Starter vs Professional)
   → Annual prepay discount

5. Close (1–2 weeks for ICP)
   → Stripe invoice or design partner renewal
```

### Pricing at this stage

| Customer type | Offer |
|---------------|-------|
| Design partner renewal | Professional at $1,199/mo (20% discount) |
| New startup (≤30 emp) | Starter $499/mo or $4,990/year |
| New SMB (30–200 emp) | Professional $1,499/mo |
| Compliance-urgent | Professional + EU AI Act pack ($2,500 setup) |

### Outbound cadence (founder)

| Activity | Weekly volume |
|----------|---------------|
| Targeted LinkedIn connections (ICP titles) | 50 |
| Personalized emails | 30 |
| Demo calls | 5–8 |
| Follow-up content (blog/post) | 1 |

**Target:** 20 qualified conversations/month → 4 demos → 1–2 closes (5–10% close rate is normal for founder-led cyber sales).

---

## 6. Phase 3 — Content & Inbound (Months 6–12)

Build inbound while continuing outbound.

### Content pillars

| Pillar | Example assets | SEO / distribution |
|--------|----------------|-------------------|
| AI attack education | “5 jailbreak patterns we block in production” | Blog, HN, Twitter/X |
| Compliance | “EU AI Act Article 15 checklist for LLM deployers” | LinkedIn, compliance newsletters |
| Technical depth | Architecture post + open-source knowledge-base samples | Dev.to, GitHub |
| Proof | Design partner case study (anonymized if needed) | Landing page |

### Lead magnets

1. **Free:** Community Docker + `aegis test-prompt` CLI
2. **Gated:** EU AI Act LLM Security Checklist PDF
3. **High-intent:** “Run your prompt through Aegis” web form (hosted demo instance)

### Conference / event strategy (low budget)

| Event type | Cost | ROI |
|------------|------|-----|
| Local BSides / OWASP chapter talk | $0 | 20–50 leads |
| Virtual AI security webinar | $500 (Zoom + ads) | 100 registrants → 10 demos |
| RSA / Black Hat booth | $15K+ | Defer until $500K ARR |

---

## 7. Phase 4 — MSP Channel (Months 9–18)

**Do not start before:** 5 non-friendly paying customers, documented sales process, 3 references ([Cyber Building Blocks channel guidance](https://cyberbuildingblocks.substack.com/p/channel-partners-are-not-a-01-motion)).

### Why MSPs

[Huntress pivoted to MSP channel](https://riffon.com/insight/ins_mlbwrav8cldk) after discovering SMBs have no IT staff — they buy through MSPs. MSPs need:
- Margin protection (flat-fee clients, incidents eat profit)
- “Hero” product that stops breaches before they bill unbillable hours
- Simple deploy (Docker) without hiring AI security experts

### MSP pitch

```
Aegis gives your clients LLM + network protection you can't build in-house.
Deploy in 30 minutes. White-label alerts. $8/endpoint wholesale → you charge $20.
We handle detection; you handle relationship.
```

### MSP recruitment

| Target | Approach |
|--------|----------|
| Pax8, Sherweb marketplaces | Apply as vendor (Year 2) |
| Local MSP meetups | Sponsor coffee; live demo |
| ConnectWise/Datto communities | Integration story (syslog → Aegis) |

**MSP target Year 2:** 5 MSP partners × 20 end clients each = 100 indirect customers

---

## 8. Distribution Channels Summary

| Channel | When | CAC | Volume potential |
|---------|------|-----|------------------|
| Founder outbound | Month 1+ | ~$0 | Low (10–20/yr) |
| Design partner program | Month 1–3 | ~$0 | 5–10 |
| Content / SEO inbound | Month 6+ | $500–2K/mo | Medium |
| Product-led (Community Docker) | Month 1+ | $0 | High top-of-funnel |
| MSP channel | Month 9+ | Partner margin | High scale |
| AWS Marketplace | Year 2 | Listing fee | Enterprise discovery |

---

## 9. Sales Collateral Checklist

| Asset | Location | Status |
|-------|----------|--------|
| Architecture diagram | `docs/ARCHITECTURE.md` | ✅ |
| Demo script | `docs/DEMO_PRESENTATION_PLAN.md` | ✅ |
| One-pager PDF | `docs/PRINTABLE_ONE_PAGER.md` | ✅ Export to PDF |
| API reference | `docs/API_REFERENCE.md` | ✅ |
| UAT / quality proof | `docs/UAT_REPORT.md` | ✅ |
| Pricing page | `docs/PRICING_STRATEGY.md` | ✅ Needs web copy |
| Case study template | Create after first partner | ⬜ |
| ROI calculator | “Cost of breach $4.8M vs $18K/year Aegis” | ⬜ |
| SOC 2 control mapping | Map Aegis to CC6/CC7 | ⬜ |

---

## 10. 90-Day Action Plan (Start Now)

### Days 1–30

- [ ] Publish landing page with ICP, pricing tiers, Calendly
- [ ] Record 3-minute demo video
- [ ] List 100 ICP companies (Crunchbase: Series A, “AI” tag, 20–200 emp)
- [ ] Send 50 personalized outreach emails
- [ ] Post Show HN / relevant Reddit launch
- [ ] Sign design partner #1

### Days 31–60

- [ ] Sign design partners #2–#4
- [ ] Publish first blog: “EU AI Act Article 15 — what LLM deployers need”
- [ ] Run first BSides/OWASP talk proposal
- [ ] Ship weekly detection accuracy report from partner feedback
- [ ] Convert partner #1 to annual (if pilot successful)

### Days 61–90

- [ ] Sign design partner #5+
- [ ] Publish case study #1
- [ ] Hire part-time SDR OR increase founder outbound to 40 emails/week
- [ ] Launch gated checklist lead magnet
- [ ] Close 3 non-partner paying customers
- [ ] Retrospective: refine ICP based on who actually paid

---

## 11. Metrics Dashboard

Track weekly:

| Metric | Year 1 target |
|--------|---------------|
| MRR | $27K by month 12 (base case) |
| Paying customers | 20 |
| Design partners converted | 50%+ |
| Demo → close rate | 15%+ |
| Churn (logo) | <10% annual |
| Community Docker pulls | 500+ |
| Inbound demo requests/month | 10+ by month 9 |
| CAC payback | <12 months |

---

## 12. What Not To Do (Common Mistakes)

1. **Free pilots for everyone** — attracts tire-kickers; charge $7.5K minimum ([Lorikeet](https://lorikeetsecurity.com/blog/founder-led-security-sales-playbook))
2. **Enterprise sales first** — 6-month cycles kill runway
3. **MSP channel before PMF** — partners sell what’s easy; you’ll get ignored ([Cyber Building Blocks](https://cyberbuildingblocks.substack.com/p/channel-partners-are-not-a-01-motion))
4. **Feature parity marketing vs HiddenLayer** — you win on unified + SMB price, not Gartner quadrant
5. **Discounting below 20%** — destroys pricing power before brand exists

---

## 13. Hiring Sequence (Revenue-Funded)

| Role | Trigger | Approx cost |
|------|---------|-------------|
| Part-time SDR | $15K MRR | $2K–4K/mo contractor |
| First AE | $40K MRR | $80K + commission |
| DevRel / technical marketer | $60K MRR | $100K |
| Customer success | 30+ customers | $90K |
| Second engineer | $80K MRR | $120K+ |

**Rule:** Do not hire sales before 5 paying customers prove the pitch works.
