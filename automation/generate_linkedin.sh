#!/usr/bin/env bash
# Generate a LinkedIn post from the latest weekly content brief using a paste-ready template.
set -euo pipefail
cd "$(dirname "$0")/.."

WEEK=$(date +%V)
BRIEF="automation/content/week-${WEEK}-brief.md"
OUT="automation/content/linkedin-draft-week-${WEEK}.md"

if [ ! -f "$BRIEF" ]; then
  python3 -m automation.gtm_engine content-week
fi

cat > "$OUT" << EOF
# LinkedIn draft — Week ${WEEK}

**Instructions:** Open Gemini Pro. Paste the prompt below + the brief from \`${BRIEF}\`.

---

## Gemini prompt

Write 2 LinkedIn posts for Aegis Sentinel (self-hosted unified AI + network security).

Audience: CTOs at 20–200 employee companies shipping LLMs.

Voice: Engineer-founder, no hype.

Post 1: EU AI Act Article 15 deadline (Aug 2026) — what to implement now.
Post 2: Live demo insight — we blocked a DAN jailbreak + port scan in one platform.

Each post: 150–220 words, hook first line, max 3 hashtags, CTA: book demo.

Brief topics:
$(grep '^- \*\*Topic' "$BRIEF" 2>/dev/null || grep 'topic' "$BRIEF" | head -5)

Product facts:
- 9 modules, MITRE ATLAS + ATT&CK, SOAR, audit chain
- From \$499/mo, design partner \$7.5K/90 days
- Beta, self-hosted Docker

---

## After Gemini generates

1. Edit for your voice (2 min)
2. Schedule in Buffer (free tier)
3. Mark calendar item published in automation/data/content_calendar.csv
EOF

echo "LinkedIn draft template: $OUT"
echo "Open in editor → copy Gemini prompt → paste brief → schedule in Buffer"
