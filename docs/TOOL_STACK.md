# Tool Stack — Maximum Value, Minimum Spend

**Your existing subscriptions (already paid):**

| Tool | Use for Aegis rollout | Monthly cost |
|------|----------------------|--------------|
| **Cursor Pro** | Landing page, automation scripts, docs, product fixes before demos | Already owned |
| **Claude Pro** | Outreach polish, blog posts, strategy, long-form content | Already owned |
| **Gemini Pro** | LinkedIn drafts, market research, Google Workspace drafts | Already owned |

**Total incremental software spend target: $0–$50/month** until first design partner revenue.

---

## Recommended stack (by function)

### CRM & outreach pipeline

| Tool | Tier | Cost | Why this one |
|------|------|------|--------------|
| **HubSpot CRM** | Free | $0 | Contacts, deals, email tracking; imports from `automation/gtm_engine.py export-hubspot` |
| **Google Sheets** | Free | $0 | Backup pipeline view; sync CSV from repo |
| **Hunter.io** | Free | $0 | 25 email searches/month for ICP contacts |
| **LinkedIn** | Free | $0 | Outbound DMs (100/month manual — do not buy Sales Nav until $15K MRR) |

**Skip for now:** Apollo ($49+), Lemlist ($59+), ZoomInfo — not worth it pre-revenue.

### Scheduling & landing page

| Tool | Tier | Cost | Why |
|------|------|------|-----|
| **Cal.com** | Free | $0 | Demo booking; link in `automation/config.json` |
| **Cloudflare Pages** or **GitHub Pages** | Free | $0 | Host `automation/landing/` static site |
| **Cloudflare** | Free | $0 | DNS + SSL for your domain |

**Skip for now:** Webflow ($14+), HubSpot CMS — build landing in Cursor.

### Email sending

| Tool | Tier | Cost | Why |
|------|------|------|-----|
| **Gmail** + **HubSpot tracking** | Free | $0 | Founder-led sends ≤50/day |
| **Brevo** (Sendinblue) | Free | $0 | 300 emails/day if you need small sequences |

**Skip for now:** Mailchimp paid, Instantly.ai — manual founder email converts better early.

### Content creation & publishing

| Tool | Tier | Cost | Why |
|------|------|------|-----|
| **Claude Pro** | Owned | $0 marginal | Blogs, email polish, case studies |
| **Gemini Pro** | Owned | $0 marginal | LinkedIn, research summaries |
| **Buffer** | Free | $0 | 3 channels, 10 scheduled posts |
| **Canva** | Free | $0 | One-pager graphics, LinkedIn carousels |
| **OBS Studio** | Free | $0 | Demo recordings (alternative to Loom) |
| **GitHub** | Free | $0 | Dev.to cross-post from repo docs |

**Optional:** Loom free tier (25 videos, 5 min) — only if OBS is too much friction.

### Automation & integrations

| Tool | Tier | Cost | Why |
|------|------|------|-----|
| **Repo scripts** | — | $0 | `automation/gtm_engine.py`, `run_weekly.sh` |
| **n8n** self-hosted | Free | $0 | Connect Cal.com → HubSpot → Slack (optional) |
| **GitHub Actions** | Free | $0 | CI + future scheduled GTM reports |

**Skip for now:** Zapier ($20+), Make.com — n8n self-hosted does the same free.

### Design partner / legal

| Tool | Tier | Cost | Why |
|------|------|------|-----|
| **Google Docs** | Free | $0 | SOW templates, proposals |
| **Stripe** | Pay per use | 2.9% | Invoicing when partner signs |
| **DocuSign** | — | Skip | Use Stripe invoice + PDF SOW until 10 customers |

---

## AI assistant routing (daily workflow)

Use the right model for the job — avoids redundant subscriptions:

```
┌─────────────────────────────────────────────────────────────┐
│                    DAILY GTM WORKFLOW                        │
├─────────────────────────────────────────────────────────────┤
│  MORNING (30 min)                                            │
│  • Run: ./automation/run_weekly.sh (Mondays) or gtm_engine   │
│  • Gemini Pro → draft 2 LinkedIn posts from content brief    │
│  • Send 5 outreach emails (HubSpot + drafts from repo)       │
├─────────────────────────────────────────────────────────────┤
│  MIDWEEK (45 min)                                            │
│  • Claude Pro → polish outreach + write 1 blog section       │
│  • Cursor Pro → landing page / product fix from demo feedback│
├─────────────────────────────────────────────────────────────┤
│  FRIDAY (20 min)                                             │
│  • Buffer → schedule next week's LinkedIn                    │
│  • Update leads.csv statuses                                 │
│  • Claude Pro → weekly retrospective (what worked?)          │
└─────────────────────────────────────────────────────────────┘
```

| Task | Best tool | Why |
|------|-----------|-----|
| Python automation, landing page, docs | **Cursor Pro** | Full repo context |
| 120-word outreach personalization | **Claude Pro** | Nuance, tone control |
| LinkedIn posts, quick research | **Gemini Pro** | Fast iteration |
| Blog 1,500+ words | **Claude Pro** | Structure + depth |
| EU AI Act research summary | **Gemini Pro** | Web grounding |
| Demo script before call | **Cursor** + `docs/DEMO_PRESENTATION_PLAN.md` | Accurate commands |
| Slide deck outline | **Claude Pro** | Narrative flow |

---

## Total cost summary

| Category | Monthly |
|----------|---------|
| Already owned (Cursor, Claude, Gemini) | $0 incremental |
| CRM, scheduling, hosting, buffer | $0 |
| Domain name | ~$12/year (~$1/mo) |
| Email (Brevo if needed) | $0 |
| **Total until revenue** | **~$1–5/mo** |

### When to add paid tools (revenue triggers)

| Tool | Add when | Cost | Trigger |
|------|----------|------|---------|
| LinkedIn Sales Navigator | $15K MRR | ~$80/mo | Outbound is working, need more leads |
| Lemlist or Instantly | $25K MRR | ~$60/mo | >50 emails/day, sequences proven |
| Loom Business | First $7.5K partner | ~$15/mo | Demo videos weekly |
| Notion Team | 2+ people on GTM | ~$10/mo | Shared playbook |
| n8n Cloud | No time to self-host | ~$20/mo | Workflow automation at scale |
| Part-time SDR | $15K MRR | $2K/mo | Founder bottleneck |

---

## Tools explicitly NOT recommended (yet)

| Tool | Why skip |
|------|----------|
| Salesforce | Overkill; HubSpot free is enough |
| Marketo / Pardot | Enterprise marketing; you have 0 customers |
| Drift / Intercom chat | No traffic yet |
| Paid ads (Google/LinkedIn) | Burn cash before PMF; do founder outbound first |
| Second AI subscription (ChatGPT Plus) | Redundant with Claude + Gemini |

---

## Setup checklist (one-time, ~2 hours)

- [ ] Copy `automation/config.example.json` → `automation/config.json`
- [ ] Create Cal.com event "Aegis Sentinel Demo (30 min)"
- [ ] Create HubSpot free account → import `automation/data/hubspot_import.csv`
- [ ] Create Buffer account → connect LinkedIn
- [ ] Register domain → point to Cloudflare Pages
- [ ] Build landing page in Cursor (`automation/prompts/cursor_landing_page.md`)
- [ ] Run `chmod +x automation/run_weekly.sh && ./automation/run_weekly.sh`

See `docs/ROLLOUT_AUTOMATION_PLAN.md` for the 12-week execution calendar.
