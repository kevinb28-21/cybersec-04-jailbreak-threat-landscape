# GTM Automation

Weekly outreach and content automation for Aegis Sentinel rollout.

**Full plan:** [`docs/ROLLOUT_AUTOMATION_PLAN.md`](../docs/ROLLOUT_AUTOMATION_PLAN.md)  
**Tool stack:** [`docs/TOOL_STACK.md`](../docs/TOOL_STACK.md)

## Quick start

```bash
cp automation/config.example.json automation/config.json
# Edit config.json: calendly_url, founder_name, founder_email

chmod +x automation/run_weekly.sh
./automation/run_weekly.sh
```

## Add leads

Edit `automation/data/leads.csv` (created from `automation/templates/leads_template.csv` on first run):

```csv
id,company,name,title,email,...,status,...
1,Acme AI,Jane Doe,CTO,jane@acme.com,...,new,...
```

## Commands

| Command | Purpose |
|---------|---------|
| `./automation/run_weekly.sh` | Full weekly prep (run every Monday) |
| `python3 -m automation.gtm_engine weekly` | Dashboard + report |
| `python3 -m automation.gtm_engine outreach-draft` | Email drafts → `outreach/drafts/` |
| `python3 -m automation.gtm_engine batch-claude` | JSON for Claude personalization |
| `python3 -m automation.gtm_engine content-week` | This week's content brief |
| `python3 -m automation.gtm_engine content-expand --force` | Regenerate 12-week calendar |
| `python3 -m automation.gtm_engine outreach-mark-sent --id 1` | Mark lead sent |
| `python3 -m automation.gtm_engine export-hubspot` | CRM import CSV |
| `./automation/generate_linkedin.sh` | Gemini-ready LinkedIn prompt |

## AI routing

| Task | Tool | Prompt file |
|------|------|-------------|
| Outreach polish | Claude Pro | `prompts/outreach_personalize.md` |
| LinkedIn + blogs | Gemini / Claude | `prompts/content_weekly.md` |
| Landing page | Cursor Pro | `prompts/cursor_landing_page.md |

Automate preparation; send outreach yourself until 10+ customers.
