#!/usr/bin/env bash
# One-command weekly GTM automation runner
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Aegis GTM Weekly Automation ==="

# Initialize if first run
if [ ! -f automation/config.json ]; then
  cp automation/config.example.json automation/config.json
  echo "Created automation/config.json — edit your Calendly URL and name first."
fi

python3 -m automation.gtm_engine init
python3 -m automation.gtm_engine content-expand 2>/dev/null || true
python3 -m automation.gtm_engine outreach-draft --status new
python3 -m automation.gtm_engine content-week
python3 -m automation.gtm_engine batch-claude
python3 -m automation.gtm_engine weekly

echo ""
echo "Next steps:"
echo "  1. Edit automation/data/leads.csv with real ICP companies"
echo "  2. Open automation/outreach/drafts/ — polish in Claude (prompts/outreach_personalize.md)"
echo "  3. Open automation/content/week-XX-brief.md — generate posts in Claude/Gemini"
echo "  4. Send emails manually or via Brevo; mark sent: python3 -m automation.gtm_engine outreach-mark-sent --id 1"
echo "  5. Import CRM: python3 -m automation.gtm_engine export-hubspot"
