"""GTM automation engine — outreach pipeline, content calendar, weekly rollups."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

AUTOMATION_DIR = Path(__file__).resolve().parent
DATA_DIR = AUTOMATION_DIR / "data"
OUTREACH_DIR = AUTOMATION_DIR / "outreach"
CONTENT_DIR = AUTOMATION_DIR / "content"
CONFIG_PATH = AUTOMATION_DIR / "config.json"

LEAD_FIELDS = [
    "id", "company", "name", "title", "email", "linkedin_url", "stage",
    "funding", "employee_count", "tech_signal", "compliance_trigger",
    "personalization_hook", "status", "last_contact", "next_action", "notes",
]

STATUS_FLOW = ["new", "researched", "draft_ready", "sent", "replied", "meeting", "partner", "lost"]

EMAIL_TEMPLATES = {
    "design_partner": {
        "subject": "LLM security + network IDS — 90-day design partner?",
        "body": """Hi {name},

I noticed {company} is {tech_signal}. We're running a small design partner program for Aegis Sentinel — self-hosted detection for prompt injection, agent tool poisoning, port scans, and runtime threats in one platform (MITRE ATLAS + SOAR).

Looking for 5 partners: $7,500 / 90-day pilot, Docker deploy, weekly tuning with the founder.

Worth a 20-minute call? {calendly_url}

{founder_name}
Founder, Aegis Sentinel""",
    },
    "followup_5d": {
        "subject": "Re: LLM security + network IDS",
        "body": """Hi {name},

Quick follow-up — still looking for 2 design partner slots this quarter. Happy to run your team through a live jailbreak + port-scan demo in 15 minutes.

{calendly_url}

{founder_name}""",
    },
    "compliance_angle": {
        "subject": "EU AI Act Article 15 — LLM security controls",
        "body": """Hi {name},

With Article 15 enforcement approaching (Aug 2026), teams shipping LLMs need documented adversarial input detection and audit trails. Aegis Sentinel is a self-hosted platform that covers prompt injection, agent/RAG attacks, and traditional network threats — with a tamper-evident audit chain for compliance evidence.

We're taking 5 design partners at $7,500 for a 90-day pilot. Interested in a short demo?

{calendly_url}

{founder_name}""",
    },
}


def load_config() -> dict[str, Any]:
    defaults = {
        "founder_name": "Founder",
        "founder_email": "founder@example.com",
        "calendly_url": "https://cal.com/your-link",
        "company_name": "Aegis Sentinel",
        "github_url": "https://github.com/kevinb28-21/cybersec-04-jailbreak-threat-landscape",
        "weekly_outreach_target": 20,
        "weekly_content_target": 3,
        "weekly_followup_target": 10,
    }
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            defaults.update(json.load(fh))
    return defaults


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def init_data_files() -> None:
    """Copy templates to working files if they don't exist."""
    leads = DATA_DIR / "leads.csv"
    calendar = DATA_DIR / "content_calendar.csv"
    if not leads.exists():
        template = AUTOMATION_DIR / "templates" / "leads_template.csv"
        if template.exists():
            leads.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    if not calendar.exists():
        seed = AUTOMATION_DIR / "templates" / "content_calendar_seed.csv"
        if seed.exists():
            calendar.write_text(seed.read_text(encoding="utf-8"), encoding="utf-8")
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(load_config(), fh, indent=2)


def pick_template(lead: dict[str, str]) -> str:
    trigger = (lead.get("compliance_trigger") or "").lower()
    if any(k in trigger for k in ("eu ai", "soc 2", "soc2", "compliance", "audit", "insurance")):
        return "compliance_angle"
    return "design_partner"


def render_email(template_key: str, lead: dict[str, str], config: dict[str, Any]) -> dict[str, str]:
    tmpl = EMAIL_TEMPLATES[template_key]
    tech = lead.get("tech_signal") or "working on AI features"
    if not tech.lower().startswith(("ship", "build", "launch", "deploy", "work")):
        tech = f"working on {tech}"
    ctx = {
        "name": lead.get("name") or "there",
        "company": lead.get("company") or "your team",
        "tech_signal": tech,
        "calendly_url": config["calendly_url"],
        "founder_name": config["founder_name"],
    }
    return {
        "subject": tmpl["subject"].format(**ctx),
        "body": tmpl["body"].format(**ctx),
        "template": template_key,
    }


def cmd_init(_: argparse.Namespace) -> int:
    init_data_files()
    OUTREACH_DIR.mkdir(parents=True, exist_ok=True)
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Initialized GTM data in {DATA_DIR}")
    print(f"Edit {CONFIG_PATH} with your Calendly URL and founder name.")
    return 0


def cmd_outreach_draft(args: argparse.Namespace) -> int:
    init_data_files()
    config = load_config()
    leads = _read_csv(DATA_DIR / "leads.csv")
    status_filter = args.status or "new"
    drafted = 0
    OUTREACH_DIR.mkdir(parents=True, exist_ok=True)

    for lead in leads:
        if (lead.get("status") or "new") != status_filter:
            continue
        if not lead.get("company") or not lead.get("name"):
            continue
        template_key = pick_template(lead)
        email = render_email(template_key, lead, config)
        lead_id = lead.get("id") or str(drafted + 1)
        out_path = OUTREACH_DIR / "drafts" / f"lead_{lead_id}_{lead['company'].replace(' ', '_')[:30]}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "lead_id": lead_id,
            "company": lead["company"],
            "name": lead["name"],
            "email": lead.get("email", ""),
            "linkedin_url": lead.get("linkedin_url", ""),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **email,
            "claude_prompt_file": "automation/prompts/outreach_personalize.md",
            "note": "Paste into Claude/Gemini for final personalization before sending.",
        }
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        lead["status"] = "draft_ready"
        drafted += 1

    _write_csv(DATA_DIR / "leads.csv", leads, LEAD_FIELDS)
    print(f"Drafted {drafted} outreach emails → {OUTREACH_DIR / 'drafts'}")
    if drafted == 0:
        print("No leads matched. Add rows to automation/data/leads.csv")
    return 0


def cmd_outreach_mark_sent(args: argparse.Namespace) -> int:
    leads = _read_csv(DATA_DIR / "leads.csv")
    today = date.today().isoformat()
    for lead in leads:
        if lead.get("id") == args.id:
            lead["status"] = "sent"
            lead["last_contact"] = today
            lead["next_action"] = f"followup { (date.today() + timedelta(days=5)).isoformat() }"
    _write_csv(DATA_DIR / "leads.csv", leads, LEAD_FIELDS)
    print(f"Marked lead {args.id} as sent.")
    return 0


def cmd_content_week(args: argparse.Namespace) -> int:
    init_data_files()
    rows = _read_csv(DATA_DIR / "content_calendar.csv")
    week_num = args.week or _current_week_number()
    week_rows = [r for r in rows if r.get("week") == str(week_num)]
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CONTENT_DIR / f"week-{week_num:02d}-brief.md"
    lines = [
        f"# Content brief — Week {week_num}",
        f"Generated: {date.today().isoformat()}",
        "",
        "Paste into Claude Pro (long form) or Gemini Pro (LinkedIn posts).",
        "Prompt file: `automation/prompts/content_weekly.md`",
        "",
        "## This week's items",
        "",
    ]
    for r in week_rows:
        lines.append(f"### {r.get('topic', 'TBD')}")
        lines.append(f"- **Date:** {r.get('date', '')}")
        lines.append(f"- **Channel:** {r.get('channel', '')}")
        lines.append(f"- **Pillar:** {r.get('pillar', '')}")
        lines.append(f"- **CTA:** {r.get('cta', '')}")
        lines.append(f"- **Status:** {r.get('status', 'planned')}")
        lines.append("")
    lines.extend([
        "## Claude/Gemini prompt",
        "",
        "```",
        "Generate content for the items above per automation/prompts/content_weekly.md",
        "```",
        "",
    ])
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Content brief: {out_path}")
    return 0


def cmd_content_expand(args: argparse.Namespace) -> int:
    """Generate 12-week content calendar from seed topics."""
    init_data_files()
    cal_path = DATA_DIR / "content_calendar.csv"
    if cal_path.exists() and not args.force:
        print(f"Calendar exists: {cal_path} (use --force to regenerate)")
        return 0

    pillars = [
        ("AI attack education", "LinkedIn", "Jailbreak pattern spotlight: {n}"),
        ("Compliance", "LinkedIn", "EU AI Act / SOC 2 angle: {n}"),
        ("Technical", "Dev.to", "Engineering deep-dive: {n}"),
        ("Proof", "LinkedIn", "Platform capability demo: {n}"),
    ]
    topics_base = [
        "DAN jailbreak detection live demo",
        "Agent tool poisoning in production",
        "RAG corpus injection risks",
        "Port scan correlation with DNS IOC",
        "Why SOAR simulation mode matters",
        "MITRE ATLAS mapping for red team findings",
        "Self-hosted vs cloud LLM firewalls cost comparison",
        "Audit chain for compliance evidence",
        "Falco runtime alerts + LLM stack",
        "Adversarial ML evasion detection",
        "Design partner program announcement",
        "Show HN launch post",
    ]
    start = date.today() - timedelta(days=date.today().weekday())
    rows: list[dict[str, str]] = []
    topic_i = 0
    for week_offset in range(12):
        week_start = start + timedelta(weeks=week_offset)
        iso_week = week_start.isocalendar()[1]
        for day_offset in range(3):
            pillar, channel, tmpl = pillars[(week_offset + day_offset) % len(pillars)]
            post_date = week_start + timedelta(days=day_offset * 2)
            topic = topics_base[topic_i % len(topics_base)]
            topic_i += 1
            rows.append({
                "week": str(iso_week),
                "date": post_date.isoformat(),
                "pillar": pillar,
                "channel": channel,
                "topic": topic if "{n}" not in tmpl else tmpl.format(n=topic),
                "cta": "Book demo" if week_offset <= 3 else "GitHub star",
                "status": "planned",
                "draft_file": "",
            })
    _write_csv(cal_path, rows, ["week", "date", "pillar", "channel", "topic", "cta", "status", "draft_file"])
    print(f"Generated 12-week calendar ({len(rows)} items) → {cal_path}")
    return 0


def _current_week_number() -> int:
    return date.today().isocalendar()[1]


def cmd_weekly(args: argparse.Namespace) -> int:
    """Print weekly GTM dashboard — outreach, content, follow-ups."""
    init_data_files()
    config = load_config()
    leads = _read_csv(DATA_DIR / "leads.csv")
    calendar = _read_csv(DATA_DIR / "content_calendar.csv")
    today = date.today()
    week_num = _current_week_number()

    new_leads = [l for l in leads if (l.get("status") or "new") == "new"]
    draft_ready = [l for l in leads if l.get("status") == "draft_ready"]
    need_followup = []
    for l in leads:
        if l.get("status") != "sent":
            continue
        na = l.get("next_action") or ""
        if "followup" in na.lower():
            try:
                parts = na.split()
                fd = date.fromisoformat(parts[-1])
                if fd <= today:
                    need_followup.append(l)
            except ValueError:
                need_followup.append(l)

    week_content = [c for c in calendar if c.get("week") == str(week_num) and c.get("status") == "planned"]

    print("=" * 60)
    print(f"AEGIS GTM WEEKLY — {today.isoformat()} (ISO week {week_num})")
    print("=" * 60)
    print(f"\n📧 OUTREACH (target: {config['weekly_outreach_target']}/week)")
    print(f"   New leads in pipeline:     {len(new_leads)}")
    print(f"   Drafts ready to send:       {len(draft_ready)}")
    print(f"   Follow-ups due today:       {len(need_followup)}")
    if new_leads[:5]:
        print("   → Run: python -m automation.gtm_engine outreach-draft")
    if need_followup[:3]:
        print("   Follow-up leads:")
        for l in need_followup[:5]:
            print(f"     • {l.get('name')} @ {l.get('company')}")

    print(f"\n📝 CONTENT (target: {config['weekly_content_target']}/week)")
    print(f"   Items planned this week:    {len(week_content)}")
    for c in week_content:
        print(f"     • [{c.get('date')}] {c.get('channel')}: {c.get('topic')[:50]}")
    print("   → Run: python -m automation.gtm_engine content-week")
    print("   → Paste brief into Claude/Gemini (automation/prompts/content_weekly.md)")

    print(f"\n🤖 AI ASSISTANT ROUTING")
    print("   Claude Pro  → blog posts, outreach polish, strategy memos")
    print("   Gemini Pro    → LinkedIn drafts, research, Google Docs export")
    print("   Cursor Pro    → landing page, scripts, repo docs")

    print(f"\n✅ CHECKLIST")
    checklist = [
        ("Send outreach drafts", len(draft_ready) > 0),
        ("Personalize 5 emails in Claude", len(new_leads) > 0),
        ("Publish 2 LinkedIn posts", len(week_content) >= 2),
        ("Run demo/UAT before any customer call", True),
        ("Update lead status after sends", True),
    ]
    for item, relevant in checklist:
        mark = "→" if relevant else " "
        print(f"   [{mark}] {item}")

    report_path = AUTOMATION_DIR / "reports" / f"weekly_{today.isoformat()}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        f"# Weekly GTM Report — {today.isoformat()}\n\n"
        f"- New leads: {len(new_leads)}\n"
        f"- Drafts ready: {len(draft_ready)}\n"
        f"- Follow-ups due: {len(need_followup)}\n"
        f"- Content items: {len(week_content)}\n",
        encoding="utf-8",
    )
    print(f"\nReport saved: {report_path}")
    return 0


def cmd_export_hubspot(args: argparse.Namespace) -> int:
    """Export leads to HubSpot-compatible CSV."""
    leads = _read_csv(DATA_DIR / "leads.csv")
    out = DATA_DIR / "hubspot_import.csv"
    hubspot_fields = ["Company", "First Name", "Last Name", "Email", "Job Title", "Lead Status", "Notes"]
    rows = []
    for l in leads:
        if not l.get("company"):
            continue
        name_parts = (l.get("name") or " ").split(" ", 1)
        rows.append({
            "Company": l.get("company", ""),
            "First Name": name_parts[0],
            "Last Name": name_parts[1] if len(name_parts) > 1 else "",
            "Email": l.get("email", ""),
            "Job Title": l.get("title", ""),
            "Lead Status": l.get("status", "new"),
            "Notes": f"tech={l.get('tech_signal','')}; compliance={l.get('compliance_trigger','')}; hook={l.get('personalization_hook','')}",
        })
    _write_csv(out, rows, hubspot_fields)
    print(f"HubSpot import file: {out} ({len(rows)} contacts)")
    return 0


def cmd_batch_claude_input(args: argparse.Namespace) -> int:
    """Build JSON batch for Claude personalization prompt."""
    leads = _read_csv(DATA_DIR / "leads.csv")
    batch = []
    for l in leads:
        if (l.get("status") or "new") not in ("new", "researched"):
            continue
        if not l.get("company"):
            continue
        batch.append({k: l.get(k, "") for k in LEAD_FIELDS})
    out_path = OUTREACH_DIR / "drafts" / "batch_input.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(batch, fh, indent=2)
    print(f"Claude batch input ({len(batch)} leads): {out_path}")
    print("Upload to Claude with automation/prompts/outreach_personalize.md")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Aegis Sentinel GTM automation")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize data files and config")

    od = sub.add_parser("outreach-draft", help="Generate outreach JSON drafts from leads.csv")
    od.add_argument("--status", default="new", help="Lead status filter")

    oms = sub.add_parser("outreach-mark-sent", help="Mark a lead as sent")
    oms.add_argument("--id", required=True)

    cw = sub.add_parser("content-week", help="Generate weekly content brief")
    cw.add_argument("--week", type=int, default=None)

    ce = sub.add_parser("content-expand", help="Generate 12-week content calendar")
    ce.add_argument("--force", action="store_true")

    sub.add_parser("weekly", help="Weekly GTM dashboard and checklist")

    sub.add_parser("export-hubspot", help="Export leads for HubSpot CRM import")

    sub.add_parser("batch-claude", help="Export leads JSON for Claude batch personalization")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    commands = {
        "init": cmd_init,
        "outreach-draft": cmd_outreach_draft,
        "outreach-mark-sent": cmd_outreach_mark_sent,
        "content-week": cmd_content_week,
        "content-expand": cmd_content_expand,
        "weekly": cmd_weekly,
        "export-hubspot": cmd_export_hubspot,
        "batch-claude": cmd_batch_claude_input,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
