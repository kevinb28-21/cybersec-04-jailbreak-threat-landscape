# Rollout Automation Plan — 12-Week Execution

**Product:** Aegis Sentinel v1.0.0-beta  
**Budget:** ~$0–5/month (leveraging Cursor Pro, Claude Pro, Gemini Pro you already own)  
**Goal:** 5 design partners + $37K–$75K pilot revenue in 90 days

Related docs: [`MASTER_PLAN.md`](MASTER_PLAN.md) · [`GO_TO_MARKET.md`](GO_TO_MARKET.md) · [`TOOL_STACK.md`](TOOL_STACK.md)

---

## Architecture: Human + AI + Scripts

```
┌──────────────────────────────────────────────────────────────────┐
│                     YOUR WEEKLY LOOP                              │
│                                                                   │
│  automation/run_weekly.sh                                         │
│       │                                                           │
│       ├── leads.csv ──► outreach drafts (JSON)                    │
│       ├── content calendar ──► week-NN-brief.md                   │
│       └── weekly report.md                                        │
│                                                                   │
│  Claude Pro ◄── polish outreach, write blogs                       │
│  Gemini Pro ◄── LinkedIn posts, research                           │
│  Cursor Pro ◄── landing page, product, scripts                     │
│                                                                   │
│  HubSpot CRM ◄── export-hubspot                                   │
│  Cal.com ◄── demo bookings                                        │
│  Buffer ◄── schedule LinkedIn                                       │
└──────────────────────────────────────────────────────────────────┘
```

**Principle:** Automate *preparation* (drafts, calendars, reports). Keep *sending* human until PMF — founder emails convert better at 0→1.

---

## One-time setup (Day 1 — 2 hours)

| Step | Action | Tool |
|------|--------|------|
| 1 | `cp automation/config.example.json automation/config.json` — fill Calendly, name, email | Repo |
| 2 | `chmod +x automation/run_weekly.sh && ./automation/run_weekly.sh` | Repo |
| 3 | Add 20 real ICP rows to `automation/data/leads.csv` | Sheets / manual |
| 4 | Create Cal.com "Aegis Demo 30min" | Cal.com free |
| 5 | Create HubSpot CRM free tier | HubSpot |
| 6 | Connect LinkedIn to Buffer free | Buffer |
| 7 | Build landing page (Cursor prompt: `automation/prompts/cursor_landing_page.md`) | Cursor Pro |
| 8 | Deploy landing to Cloudflare Pages or GitHub Pages | Free hosting |
| 9 | Record 3-min demo (OBS or Loom free) | OBS |
| 10 | Optional: import n8n workflow (`automation/workflows/n8n-cal-hubspot.md`) | n8n self-hosted |

---

## Weekly rhythm (every Monday, 90 minutes)

| Time | Task | Command / tool |
|------|------|----------------|
| 0:00 | Run automation | `./automation/run_weekly.sh` |
| 0:10 | Review weekly report | `automation/reports/weekly_YYYY-MM-DD.md` |
| 0:20 | Personalize 5 outreach emails | Claude + `automation/prompts/outreach_personalize.md` |
| 0:40 | Send 5 emails + 5 LinkedIn connection notes | Gmail + HubSpot |
| 0:50 | Generate 2 LinkedIn posts | Gemini + `automation/content/week-NN-brief.md` |
| 1:00 | Schedule posts in Buffer | Buffer |
| 1:10 | Mark leads sent | `python3 -m automation.gtm_engine outreach-mark-sent --id N` |
| 1:20 | Product: fix one demo bug if needed | Cursor Pro |

**Daily (15 min, Tue–Fri):**
- Send 3–5 more outreach emails
- Comment on 3 AI security LinkedIn posts (visibility)
- Reply to any demo replies within 4 hours

---

## 12-week calendar

### Weeks 1–4: Foundation + first partners

| Week | Outreach | Content | Product | Milestone |
|------|----------|---------|---------|-----------|
| **1** | 20 emails (network list) | 2 LinkedIn: EU AI Act + jailbreak demo | Landing page live | Config + pipeline running |
| **2** | 20 cold emails | 1 blog: "Why 3 vendors fail SMBs" | Demo video published | 3 discovery calls booked |
| **3** | 20 emails + follow-ups | Show HN draft in Cursor | UAT green before calls | Show HN posted |
| **4** | 15 emails | Case study template | Partner #1 onboarded | **Design partner #1 signed** |

**Automation focus:**
```bash
# Every Monday
./automation/run_weekly.sh

# After adding leads
python3 -m automation.gtm_engine outreach-draft
python3 -m automation.gtm_engine batch-claude   # upload to Claude
```

### Weeks 5–8: Convert + prove

| Week | Outreach | Content | Milestone |
|------|----------|---------|-----------|
| **5** | 20 emails, compliance angle | LinkedIn: audit chain for SOC 2 | Partner #2 signed |
| **6** | Follow-up wave (automation flags due) | Dev.to: tiered detection architecture | 2 case studies in progress |
| **7** | 20 emails to fintech/healthtech | LinkedIn: agent poisoning demo | Partner #3 signed |
| **8** | Referrals from partners | Blog: EU AI Act checklist PDF (lead magnet) | **$22K+ pilot revenue** |

**Lead magnet automation:**
1. Claude Pro writes checklist from `docs/MARKET_RESEARCH.md` §5
2. Gemini formats as PDF via Google Docs
3. Landing page email gate → HubSpot form
4. Brevo sends auto-reply with PDF link

### Weeks 9–12: Scale inbound + prepare GA

| Week | Outreach | Content | Milestone |
|------|----------|---------|-----------|
| **9** | 15 emails + MSP research list | Partner #1 case study published | Inbound demo requests |
| **10** | 10 emails (quality > quantity) | Webinar: "LLM security in 15 min" (Zoom free) | 50 webinar registrants |
| **11** | MSP outreach (5 targets) | LinkedIn: design partner spots closing | Partner #4–5 signed |
| **12** | Retrospective | Year 1 GTM blog post | **5 partners, $37K+ revenue, 20 paying pipeline** |

---

## Automation command reference

```bash
# Initialize (first time)
python3 -m automation.gtm_engine init

# Weekly dashboard (run every Monday)
python3 -m automation.gtm_engine weekly

# Full weekly prep (recommended)
./automation/run_weekly.sh

# Generate outreach drafts from leads.csv
python3 -m automation.gtm_engine outreach-draft --status new

# Export for Claude batch personalization
python3 -m automation.gtm_engine batch-claude

# Mark lead as sent after emailing
python3 -m automation.gtm_engine outreach-mark-sent --id 3

# Content brief for this week
python3 -m automation.gtm_engine content-week

# Generate 12-week content calendar (once)
python3 -m automation.gtm_engine content-expand --force

# HubSpot CRM import file
python3 -m automation.gtm_engine export-hubspot
```

---

## Outreach automation flow

```
1. RESEARCH (manual, 5 min/lead)
   Hunter.io free → find email
   LinkedIn → tech_signal, personalization_hook
   ↓
2. ADD ROW to automation/data/leads.csv
   ↓
3. SCRIPT generates draft JSON
   python3 -m automation.gtm_engine outreach-draft
   ↓
4. CLAUDE polishes (automation/prompts/outreach_personalize.md)
   ↓
5. YOU send via Gmail (HubSpot tracks opens)
   ↓
6. MARK SENT
   python3 -m automation.gtm_engine outreach-mark-sent --id N
   ↓
7. DAY 5: followup template auto-selected on next weekly run
```

**Volume targets:**

| Period | Emails/week | LinkedIn DMs/week | Demos/week |
|--------|-------------|-------------------|------------|
| Weeks 1–4 | 20 | 10 | 2 |
| Weeks 5–8 | 15 | 10 | 3 |
| Weeks 9–12 | 10 | 5 | 2 |

---

## Content automation flow

```
1. content-expand generates 12-week calendar (once)
   ↓
2. content-week generates Monday brief
   ↓
3. GEMINI → 2 LinkedIn posts (fast)
   CLAUDE → 1 blog section (deep)
   ↓
4. BUFFER schedules posts
   ↓
5. Repurpose prompt (content_weekly.md) → thread + carousel
   ↓
6. Update content_calendar.csv status → published
```

**Content mix (from GO_TO_MARKET):**

| Pillar | % | Channels |
|--------|---|----------|
| AI attack education | 35% | LinkedIn, Dev.to |
| Compliance (EU AI Act) | 30% | LinkedIn, PDF lead magnet |
| Technical proof | 25% | HN, GitHub, blog |
| Social proof | 10% | Case studies, partner quotes |

---

## n8n workflow (optional, free self-hosted)

See `automation/workflows/n8n-cal-hubspot.md` for:
- Cal.com booking → HubSpot deal created
- HubSpot deal stage → Slack reminder
- Weekly cron → trigger `gtm_engine weekly` → email report

---

## Metrics dashboard (track in HubSpot + weekly report)

| Metric | Week 4 target | Week 12 target |
|--------|---------------|----------------|
| Leads in CSV | 50 | 150 |
| Emails sent | 60 | 200 |
| Demo calls | 4 | 20 |
| Design partners signed | 1 | 5 |
| Pilot revenue | $7.5K | $37K+ |
| LinkedIn posts published | 8 | 30 |
| GitHub stars | 50 | 200 |
| Inbound demo requests/mo | 0 | 5 |

---

## AI prompt files (repo)

| File | Use with | Purpose |
|------|----------|---------|
| `automation/prompts/outreach_personalize.md` | Claude Pro | Email + LinkedIn DM |
| `automation/prompts/content_weekly.md` | Claude + Gemini | Posts + blogs |
| `automation/prompts/cursor_landing_page.md` | Cursor Pro | Landing page build |

---

## Decision: what NOT to automate yet

| Activity | Why keep human |
|----------|----------------|
| First email send | Personalization quality = reply rate |
| Demo calls | Learn ICP; refine pitch |
| Pricing negotiation | Design partner feedback |
| LinkedIn comments | Authenticity builds trust |
| Show HN replies | Community expects founder voice |

Automate when: 10+ customers, proven email template >15% reply rate, then consider Lemlist.

---

## Success criteria (90 days)

- [ ] `./automation/run_weekly.sh` runs every Monday without errors
- [ ] 5 design partners signed ($7.5K–$15K each)
- [ ] Landing page live with Cal.com + lead magnet
- [ ] 30+ LinkedIn posts published via Buffer
- [ ] HubSpot pipeline reflects all leads
- [ ] 2 published case studies
- [ ] Show HN completed with 100+ upvotes goal

**Then proceed to:** GA release (`docs/PRODUCT_RELEASE.md`), Stripe billing, first MSP conversation.

---

## File index

```
automation/
├── config.example.json      # Copy → config.json
├── gtm_engine.py            # Main automation CLI
├── run_weekly.sh            # One-command weekly runner
├── data/
│   ├── leads.csv            # Outreach pipeline (you maintain)
│   ├── leads_template.csv
│   └── content_calendar.csv # Auto-generated
├── outreach/drafts/         # Generated email JSON
├── content/                 # Weekly content briefs
├── reports/                 # Weekly GTM reports
├── prompts/                 # Claude/Gemini/Cursor prompts
└── workflows/               # n8n optional integrations
```

Update [`MASTER_PLAN.md`](MASTER_PLAN.md) §17 when completing each weekly milestone.
