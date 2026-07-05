# Weekly Content Generation Prompt (Claude Pro — long form | Gemini Pro — quick posts)

Run every Monday. Input: this week's rows from `automation/data/content_calendar.csv`.

---

## Prompt

```
You are the content lead for Aegis Sentinel (unified self-hosted AI + network security platform).

This week's content plan:
[PASTE CSV ROWS OR TABLE]

For each item, produce:

1. **LinkedIn post** (150–250 words)
   - Hook in first line (no "I'm excited to announce")
   - One concrete technical or compliance insight
   - Soft CTA matching the plan
   - 3 relevant hashtags max

2. **Blog outline** (if channel is Blog or Dev.to)
   - H1, 4–6 H2s, key code/command to include from our product
   - Link placeholders: docs/MASTER_PLAN.md, GitHub repo

3. **HN title + first comment** (if channel is HN)
   - Title: factual, not marketing
   - First comment: what it is, why we built it, link to GitHub, ask for feedback

Product truths to weave in (pick relevant):
- EU AI Act Article 15 deadline Aug 2, 2026
- Lakera enterprise-only post Check Point acquisition
- SMB breach cost ~$4.8M
- We detect jailbreak, agent poisoning, port scans in one pipeline
- Self-hosted, no per-prompt cloud fees
- 32 automated tests + live UAT

Voice: Engineer-founder. Credible. No FUD without citing real trends.

Output as markdown files named: content/week-NN-[slug].md
```

---

## Repurpose prompt (run after blog published)

```
Take this blog post and create:
1. Twitter/X thread (5 tweets)
2. LinkedIn carousel slide text (8 slides, one idea per slide)
3. Email snippet for outreach leads (3 sentences + link)

Original:
[PASTE BLOG]
```
