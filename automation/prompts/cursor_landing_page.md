# Cursor Pro Prompt — Landing Page + GTM Assets

Use in Cursor Agent with repo context (@docs/MASTER_PLAN.md @docs/PRICING_STRATEGY.md).

---

## Landing page (static HTML or Next.js)

```
Build a single-page marketing site in automation/landing/ that:

1. Hero: "Unified AI + network security. Self-hosted. From $499/mo."
2. Problem: 3 vendor problem (LLM firewall + UTM + SOAR costs)
3. Demo video embed placeholder + "Book demo" CTA button → CALENDLY_URL env
4. 9 module grid with icons (text-only ok)
5. Pricing table from docs/PRICING_STRATEGY.md (Community, Starter, Professional, Business)
6. EU AI Act Aug 2026 compliance callout
7. Footer: GitHub link, docs link, contact email

Style: Dark theme, teal accent #0d9488, mobile-first, no external CSS frameworks required (or Tailwind if already in project).
Deploy target: GitHub Pages or Cloudflare Pages.
Include config for CALENDLY_URL and CONTACT_EMAIL in a config.json.
```

---

## Weekly automation script

```
Add to automation/gtm_engine.py a command:
  python -m automation.gtm_engine weekly

That prints this week's outreach targets, content due, and follow-ups from CSV data.
Match existing repo Python style. No new dependencies beyond stdlib + csv.
```

---

## Email signature HTML

```
Generate a professional email signature HTML for Aegis Sentinel founder with:
- Logo placeholder
- One-line tagline
- Links: website, GitHub, book demo
- "Aegis Sentinel v1.0.0-beta — 9 modules, 1 platform"
```
