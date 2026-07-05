# Market Research — Aegis Sentinel

**Prepared for:** Product & GTM planning  
**Date:** July 2026  
**Status:** Research-backed; figures sourced from published industry reports

---

## Executive Summary

Aegis Sentinel sits at the intersection of three fast-growing markets:

1. **AI / LLM security** (~$2.0–2.6B in 2026, 22–31% CAGR)
2. **Agentic AI security** (~$1.65B in 2026, 42% CAGR to 2032)
3. **SMB unified security / UTM** (~$4.3–10.6B SMB segment, 11–14% CAGR)

No incumbent owns all three in a single self-hostable platform. Point solutions (Lakera, Prompt Armor) cover LLM runtime only. UTM vendors (Fortinet, Sophos) cover network/endpoint but not MITRE ATLAS agent/RAG/VLM threats. SOAR platforms (Cortex XSOAR, Tines) start at $24K–$300K/year and require mature SOC staff.

**Aegis’s wedge:** Unified detection + correlation + SOAR for companies deploying LLMs *and* operating a network — at SMB-accessible price points, self-hosted for data sovereignty, with EU AI Act Article 15 alignment as a compliance narrative.

---

## 1. AI Prompt & LLM Security Market

### Market size (2025–2030)

| Source | 2025/2026 Value | Forecast | CAGR |
|--------|-----------------|----------|------|
| [The Business Research Company](https://www.thebusinessresearchcompany.com/report/artificial-intelligence-ai-prompt-security-global-market-report) | $1.98B (2025) → $2.61B (2026) | $7.69B by 2030 | 31.3% |
| [Market Intelo — Prompt Injection Prevention](https://marketintelo.com/report/prompt-injection-prevention-market) | $1.8B (2025) → $2.21B (2026) | $11.2B by 2034 | 22.4% |
| [Research and Markets](https://www.researchandmarkets.com/reports/6226426/ai-prompt-security-market-report) | $2.61B (2026) | $7.69B by 2030 | 31.1% |

**Takeaway:** Even conservative estimates place the addressable AI prompt security market above **$2 billion in 2026**, growing toward **$7–11 billion** within 8 years.

### Growth drivers (documented)

- Enterprise LLM deployment at scale (chatbots, copilots, RAG apps)
- Prompt injection and jailbreak incidents in production
- Data leakage via LLM outputs and tool calls
- Regulatory pressure (EU AI Act Article 15 — accuracy, robustness, **cybersecurity** for high-risk AI)
- Managed detection and response extending to AI workloads

### Segment breakdown (Market Intelo)

- **Software:** largest/fastest-growing component (~38.5% share; ~26% CAGR for software)
- **Cloud deployment:** ~24% CAGR vs ~19% on-premises
- **North America:** ~42% revenue share (largest region)
- **Enterprise size:** large enterprises dominate today; SMB adoption accelerating

---

## 2. Agentic AI Security Market

| Metric | Value | Source |
|--------|-------|--------|
| 2026 market size | $1.65B | [MarketsandMarkets](https://www.marketsandmarkets.com/Market-Reports/agentic-ai-security-market-97017233.html) |
| 2032 forecast | $13.52B | Same |
| CAGR 2026–2032 | 42.0% | Same |

**Relevance to Aegis:** Projects 05 (agent-guard), 06 (rag-guard), 07 (vlm-guard), and 08 (runtime-guard) map directly to agentic AI threat categories: tool poisoning, RAG injection, multimodal attacks, container/runtime escape. This is the **fastest-growing sub-segment** of AI security.

**Notable competitors named in industry reports:** Protect AI, HiddenLayer, Lakera — all enterprise-focused, quote-based pricing.

---

## 3. SMB & Unified Security Market

### SMB integrated security appliances

| Metric | Value | Source |
|--------|-------|--------|
| 2025 market | $4.3B | [Market Intelo — SMB Integrated Security](https://marketintelo.com/report/smb-integrated-security-appliances-market) |
| 2034 forecast | $10.8B | Same |
| CAGR | 11.5% | Same |
| UTM share of SMB appliances | 47.2% (~$2.03B) | Same |

### Unified Threat Management (broader)

| Metric | Value | Source |
|--------|-------|--------|
| 2025 market | $9.32B | [Mordor Intelligence — UTM](https://www.mordorintelligence.com/industry-reports/unified-threat-management-market) |
| 2026 → 2031 | $10.56B → $19.75B | Same |
| SME segment CAGR | 14.48% (faster than overall) | Same |

### SMB cybersecurity spending behavior

From [Market Intelo — SMB Cybersecurity](https://marketintelo.com/report/smb-cybersecurity-market):

- **Endpoint/security bundles:** $5–$35 per endpoint/month (Cisco, Fortinet, Sophos, CrowdStrike)
- **MSSP flat fees:** $500–$5,000/month depending on scope
- **Small business (<20 employees):** $200–$800/month total security stack
- **Medium business (100–500 employees):** $3,000–$25,000/month
- **Average SMB breach cost (2025):** ~$4.8M — strong ROI argument for security spend
- **~45% of cyberattacks** target organizations with fewer than 1,000 employees

**Takeaway:** SMBs buy **bundled, predictable pricing**. They do not buy six point products. Aegis’s unified platform matches how SMBs already purchase security.

---

## 4. SOAR & Security Automation Market

SOAR does not have standardized per-endpoint pricing. From [CIOPages SOAR Buyer Guide](https://www.ciopages.com/buyer-guides/security-orchestration-automation) and [Ciphers Security 2026 comparison](https://cipherssecurity.com/best-soar-platforms-in-2026/):

| Platform | Typical annual cost | Model |
|----------|---------------------|-------|
| Tines | Free tier (500 actions/day); paid from ~$30K/yr | Consumption + tier |
| Torq | From ~$24K/yr | Quote-based |
| Cortex XSOAR | $50K–$300K+/yr | Per-seat + automation volume |
| Splunk SOAR | Enterprise tier (five-to-six figures) | Bundled with Splunk ES |
| Mid-market budget guidance | $40K–$150K/yr (200–1,000 employees) | [Zendikt 2026 SOAR guide](https://www.zendikt.com/top-10-soar-software) |

**Managed SOAR alternative:** UnderDefense MAXI publishes **$11–15/endpoint/month** for fully managed detection + response ([UnderDefense 2026 guide](https://underdefense.com/blog/security-automation-tools/)).

**Aegis opportunity:** Built-in YAML playbooks + simulation mode gives SOAR-like capability without a $30K+ standalone contract. This is a **differentiation story for SMBs** that cannot afford Cortex XSOAR.

---

## 5. Regulatory Tailwinds

### EU AI Act — Article 15 (Cybersecurity for high-risk AI)

Source: [EU AI Act Article 15](https://artificialintelligenceact.eu/article/15/) and [EU AI Act Service Desk](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15)

High-risk AI systems must be resilient against:

- Data poisoning and model poisoning
- Adversarial examples / model evasion
- Unauthorized manipulation of outputs
- Confidentiality attacks

**Enforcement timeline:** High-risk system obligations become enforceable **August 2, 2026** ([CSA Research Note](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-compliance-deadline-20/)).

**Aegis mapping:**

| EU AI Act requirement | Aegis capability |
|----------------------|------------------|
| Detect adversarial inputs | Tiered detector + adversarial-ml module |
| Prevent prompt manipulation | aisec-guard, agent-guard, rag-guard |
| Logging for audit | Tamper-evident audit chain |
| Runtime monitoring | runtime-guard, watchdog |
| Post-market monitoring | Alert correlation, feedback loop |

This is a **compliance-led sales narrative** for EU and global enterprises with EU exposure.

---

## 6. Competitive Landscape

### AI security point solutions

| Vendor | Focus | Pricing (2026) | Gap vs Aegis |
|--------|-------|----------------|--------------|
| [Lakera Guard](https://www.lakera.ai/blog/llm-security-tools) | LLM prompt/output firewall | Enterprise-only post Check Point acquisition (~$25K+/yr cited by [RuneSec](https://runesec.dev/alternatives/lakera-guard)); formerly ~$99/mo self-serve | No network/endpoint/SOAR |
| [Prompt Armor](https://runesec.dev/alternatives/lakera-guard) | Prompt injection API | Cloud API, quote-based | Injection only |
| [HiddenLayer](https://www.hiddenlayer.com/) | Full AI lifecycle security | $30K–$150K/yr typical ([CostBench](https://costbench.com/software/ai-security/hiddenlayer/)); AWS Marketplace lists up to $5M for full platform | Enterprise-only; not SMB-priced |
| [Protect AI](https://costbench.com/software/ai-security/hiddenlayer/) | Model supply chain + runtime | Up to ~$100K/yr | Heavy MLOps focus |
| Open-source (LLM Guard, NeMo Guardrails) | App-layer guardrails | Free | No unified SOC, correlation, SOAR |

### Traditional security (network/endpoint)

| Vendor | Focus | Pricing | Gap vs Aegis |
|--------|-------|---------|--------------|
| Fortinet / Sophos / Cisco UTM | Firewall, IPS, AV | $5–$35/endpoint/mo | No LLM/agent/RAG modules |
| CrowdStrike / SentinelOne | EDR | Per-endpoint subscription | No AI-specific ATLAS coverage |

### Aegis positioning matrix

```
                    AI-native depth
                         ▲
                         │
           Lakera ●      │      ● HiddenLayer
           Prompt Armor ●│
                         │         ★ Aegis Sentinel
                         │           (AI + Network + SOAR)
           Open-source ● │
                         │
    ─────────────────────┼─────────────────────► Unified platform breadth
                         │
           Fortinet ●    │    ● Splunk SOAR
           Sophos ●      │    ● Cortex XSOAR
                         │
```

**Unique position:** Only product in this repo’s competitive set combining **9 modules**, **MITRE ATT&CK + ATLAS**, **self-hosted deployment**, and **integrated SOAR** at SMB-accessible economics.

---

## 7. Market Fit Assessment for Aegis Sentinel

### Strong fit (primary ICP)

| Segment | Why they buy | Pain Aegis solves |
|---------|--------------|-------------------|
| **Series A–C startups deploying LLMs** | Need SOC 2 / ISO; fast decisions; no SOC team | One API for prompt + agent + RAG security; audit chain for compliance |
| **SMBs with AI copilots (20–200 employees)** | Cannot afford Lakera + Fortinet + SOAR separately | Unified platform, Docker deploy in 5 minutes |
| **MSPs serving SMB clients** | Need margin-protecting security SKU | White-label potential; per-endpoint packaging |
| **EU companies with high-risk AI (Aug 2026 deadline)** | Article 15 compliance | Documented detection + logging + red-team import |

### Moderate fit (year 2+)

| Segment | Blocker today | Path |
|---------|---------------|------|
| Enterprise (5,000+ employees) | Needs FedRAMP, 750+ integrations, 24/7 SOC | Partner with MSSP; build enterprise tier |
| Pure network-only shops | Don't use LLMs | Lead with net-sentinel + host-shield only |

### Weak fit (avoid early)

| Segment | Why |
|---------|-----|
| Companies with no AI and no compliance pressure | Discretionary purchase; long sales cycle |
| Enterprise requiring on-prem SOAR with 900 integrations | Aegis is not Cortex XSOAR |

---

## 8. Total Addressable Market (TAM) — Bottom-Up for Aegis

**Method:** Serviceable Obtainable Market (SOM) focus for a pre-revenue startup.

### TAM (theoretical maximum)

- AI prompt security: **$2.6B** (2026)
- Plus SMB UTM/security overlap: **$4.3B**
- Combined TAM (with overlap adjustment ~30%): **~$5–6B** addressable for unified AI+network security

### SAM (realistic segment for Aegis v1)

Companies that:
- Deploy LLM or agent features in production
- Have 20–500 employees
- Spend $500–$5,000/month on security
- Prefer self-hosted or VPC deployment

**Estimate:** ~150,000 such companies globally (growth-stage tech + SMB in NA/EU). At $18K average ACV → **~$2.7B SAM**.

### SOM (achievable in 3 years without massive funding)

| Year | Target customers | Avg ACV | ARR |
|------|------------------|---------|-----|
| Year 1 | 15–25 | $15K–$24K | $225K–$600K |
| Year 2 | 50–80 | $20K–$30K | $1.0M–$2.4M |
| Year 3 | 120–200 | $24K–$36K | $2.9M–$7.2M |

These are **founder-led sales** assumptions, consistent with [Lorikeet Security’s first-50-customers playbook](https://lorikeetsecurity.com/blog/founder-led-security-sales-playbook).

---

## 9. Key Market Facts (Quick Reference)

| Fact | Value | Source |
|------|-------|--------|
| AI prompt security market 2026 | $2.0–2.6B | TBRC, Market Intelo |
| Agentic AI security CAGR | 42% | MarketsandMarkets |
| SMB breach average cost | ~$4.8M | Market Intelo SMB report |
| Attacks on orgs <1,000 employees | ~45% | UTM appliance report |
| SOAR mid-market floor | ~$24K–$40K/yr | Ciphers, Zendikt |
| Endpoint security SMB range | $5–$35/endpoint/mo | Market Intelo |
| EU AI Act high-risk deadline | Aug 2, 2026 | CSA, EU AI Act |
| Lakera acquisition | ~$187M by Check Point (Oct 2025) | RuneSec — validates AI security M&A |

---

## 10. Research Limitations

- Most market reports are paid; figures above come from report summaries and executive summaries, not full PDFs.
- Competitor pricing is often quote-based; ranges are industry estimates, not list prices.
- Aegis is v1.0.0-beta — market fit must be validated with paying design partners, not assumed from feature parity alone.

**Next validation step:** 10 paid design-partner engagements at $7.5K–$15K (see `GO_TO_MARKET.md`) to confirm willingness-to-pay before scaling marketing spend.
