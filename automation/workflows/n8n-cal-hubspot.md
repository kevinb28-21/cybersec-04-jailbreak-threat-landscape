# n8n Workflow — Cal.com → HubSpot → Weekly GTM Report

**Cost:** $0 (self-hosted n8n)  
**When to set up:** After HubSpot + Cal.com are configured (Week 1)

---

## Prerequisites

1. n8n self-hosted: `docker run -it --rm --name n8n -p 5678:5678 -v n8n_data:/home/node/.n8n n8nio/n8n`
2. HubSpot free account + private app token
3. Cal.com webhook on booking created
4. Repo cloned on a machine that can run `python3 -m automation.gtm_engine weekly`

---

## Workflow 1: New demo booking → HubSpot deal

**Trigger:** Cal.com webhook `BOOKING_CREATED`

**Steps:**
1. **Webhook** — receive Cal.com payload
2. **Set** — extract `attendee.email`, `attendee.name`, `eventTitle`
3. **HubSpot — Create or update contact** — email, firstname, lastname
4. **HubSpot — Create deal** — name: `Aegis Demo — {{company}}`, stage: `appointmentscheduled`, amount: `7500`
5. **Slack / Email** — notify founder: "New demo booked: {{email}}"

**Cal.com webhook URL:** `https://your-n8n.example.com/webhook/aegis-demo-booked`

---

## Workflow 2: Weekly GTM report (cron)

**Trigger:** Cron — `0 8 * * 1` (Monday 8am)

**Steps:**
1. **Execute Command** (SSH node or local)
   ```bash
   cd /path/to/repo && ./automation/run_weekly.sh
   ```
2. **Read Binary File** — `automation/reports/weekly_*.md` (latest)
3. **Gmail / Brevo** — email report to founder
4. **Optional Slack** — post summary to `#gtm` channel

---

## Workflow 3: Lead status sync (manual trigger)

**Trigger:** Manual or when `leads.csv` updated in Google Sheets

**Steps:**
1. **Google Sheets** — read outreach pipeline tab
2. **Code** — map columns to HubSpot format
3. **HubSpot — Batch upsert contacts**
4. **Filter** — status = `meeting` → create task "Prepare demo"

---

## Workflow 4: Content reminder

**Trigger:** Cron — `0 9 * * 3` (Wednesday 9am)

**Steps:**
1. **Execute Command**
   ```bash
   python3 -m automation.gtm_engine content-week
   ```
2. **Email** — send `automation/content/week-NN-brief.md` to founder with subject "Content due this week — paste into Gemini"

---

## Import into n8n

1. Open n8n → Workflows → Import from JSON (build manually using steps above)
2. Store exported workflow at `automation/workflows/n8n/demo-booking-hubspot.json` once configured
3. Credentials: HubSpot OAuth, Gmail OAuth, Cal.com webhook secret

---

## Without n8n (minimal stack)

If you skip n8n entirely, the bash script `./automation/run_weekly.sh` plus manual Cal.com → HubSpot entry (2 min/booking) is sufficient until 10 customers.

**Recommended path:** Weeks 1–8 manual. Add n8n at Week 9 if demo volume >5/week.
