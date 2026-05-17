"""
jailbreak_taxonomy.py
Jailbreak-as-a-Service Threat Landscape
----------------------------------------
Defines the data model for the jailbreak taxonomy, loads the technique database,
provides categorisation, filtering, export, and MITRE ATLAS mapping utilities.

Usage:
    python jailbreak_taxonomy.py --list-all
    python jailbreak_taxonomy.py --category "Prompt Injection"
    python jailbreak_taxonomy.py --severity CRITICAL
    python jailbreak_taxonomy.py --export csv --output results/taxonomy.csv
    python jailbreak_taxonomy.py --stats
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_TAXONOMY_PATH = Path(__file__).parent / "techniques" / "jailbreak_techniques.json"
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MitreAtlasMapping:
    """Represents a single MITRE ATLAS tactic/technique mapping."""
    atlas_id: str
    tactic: str
    technique: str
    url: str = field(init=False)

    def __post_init__(self) -> None:
        base = "https://atlas.mitre.org/techniques"
        self.url = f"{base}/{self.atlas_id.replace('.', '/')}/"

    def to_dict(self) -> Dict[str, str]:
        return {
            "atlas_id": self.atlas_id,
            "tactic": self.tactic,
            "technique": self.technique,
            "url": self.url,
        }


@dataclass
class JailbreakTechnique:
    """Full representation of a single jailbreak technique."""
    id: str
    name: str
    category: str
    subcategory: str
    description: str
    example_prompt: str
    mitre_atlas_id: str
    mitre_atlas_tactic: str
    mitre_atlas_technique: str
    severity: str
    effectiveness_rating: int          # 1 (lowest) – 5 (highest)
    first_documented: str
    affected_models: List[str]
    defense_recommendations: List[str]
    tags: List[str]

    # Derived
    mitre_mapping: MitreAtlasMapping = field(init=False)
    severity_score: int = field(init=False)

    def __post_init__(self) -> None:
        self.mitre_mapping = MitreAtlasMapping(
            atlas_id=self.mitre_atlas_id,
            tactic=self.mitre_atlas_tactic,
            technique=self.mitre_atlas_technique,
        )
        self.severity_score = SEVERITY_ORDER.get(self.severity, 0)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JailbreakTechnique":
        return cls(
            id=data["id"],
            name=data["name"],
            category=data["category"],
            subcategory=data["subcategory"],
            description=data["description"],
            example_prompt=data["example_prompt"],
            mitre_atlas_id=data["mitre_atlas_id"],
            mitre_atlas_tactic=data["mitre_atlas_tactic"],
            mitre_atlas_technique=data["mitre_atlas_technique"],
            severity=data["severity"],
            effectiveness_rating=data["effectiveness_rating"],
            first_documented=data["first_documented"],
            affected_models=data["affected_models"],
            defense_recommendations=data["defense_recommendations"],
            tags=data["tags"],
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["mitre_mapping"] = self.mitre_mapping.to_dict()
        return d

    def risk_score(self) -> float:
        """Simple composite risk score: severity * effectiveness / 5.0."""
        return round(self.severity_score * self.effectiveness_rating / 5.0, 2)

    def short_summary(self) -> str:
        return (
            f"[{self.id}] {self.name} | {self.category} | "
            f"Severity: {self.severity} | Effectiveness: {self.effectiveness_rating}/5 | "
            f"MITRE: {self.mitre_atlas_id}"
        )

    def __repr__(self) -> str:
        return f"JailbreakTechnique(id={self.id!r}, name={self.name!r}, severity={self.severity!r})"


# ---------------------------------------------------------------------------
# Taxonomy manager
# ---------------------------------------------------------------------------

class JailbreakTaxonomy:
    """
    Central store for the jailbreak technique database.

    Provides loading, filtering, export, and statistical analysis of
    the technique catalogue.
    """

    def __init__(self, taxonomy_path: Path = DEFAULT_TAXONOMY_PATH) -> None:
        self.taxonomy_path = taxonomy_path
        self.techniques: List[JailbreakTechnique] = []
        self.metadata: Dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    def _load(self) -> None:
        """Load and parse the JSON taxonomy file."""
        if not self.taxonomy_path.exists():
            raise FileNotFoundError(
                f"Taxonomy file not found: {self.taxonomy_path}\n"
                "Ensure techniques/jailbreak_techniques.json is present."
            )
        with open(self.taxonomy_path, encoding="utf-8") as fh:
            raw = json.load(fh)

        self.metadata = {
            k: v for k, v in raw.items()
            if k not in ("techniques",)
        }
        self.techniques = [JailbreakTechnique.from_dict(t) for t in raw["techniques"]]

    def reload(self) -> None:
        """Reload the taxonomy from disk (useful after file edits)."""
        self.techniques.clear()
        self._load()

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------
    def get_by_id(self, technique_id: str) -> Optional[JailbreakTechnique]:
        for t in self.techniques:
            if t.id.upper() == technique_id.upper():
                return t
        return None

    def filter_by_category(self, category: str) -> List[JailbreakTechnique]:
        cat_lower = category.lower()
        return [t for t in self.techniques if cat_lower in t.category.lower()]

    def filter_by_severity(self, severity: str) -> List[JailbreakTechnique]:
        return [t for t in self.techniques if t.severity.upper() == severity.upper()]

    def filter_by_tag(self, tag: str) -> List[JailbreakTechnique]:
        tag_lower = tag.lower()
        return [t for t in self.techniques if tag_lower in t.tags]

    def filter_by_effectiveness(self, min_rating: int) -> List[JailbreakTechnique]:
        return [t for t in self.techniques if t.effectiveness_rating >= min_rating]

    def filter_by_mitre_id(self, atlas_id: str) -> List[JailbreakTechnique]:
        return [t for t in self.techniques if t.mitre_atlas_id == atlas_id]

    def search(self, query: str) -> List[JailbreakTechnique]:
        """Full-text search across name, description, and tags."""
        q = query.lower()
        results = []
        for t in self.techniques:
            if (q in t.name.lower()
                    or q in t.description.lower()
                    or any(q in tag for tag in t.tags)):
                results.append(t)
        return results

    def top_risk(self, n: int = 10) -> List[JailbreakTechnique]:
        """Return the N highest-risk techniques by composite risk score."""
        return sorted(self.techniques, key=lambda t: t.risk_score(), reverse=True)[:n]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def statistics(self) -> Dict[str, Any]:
        """Compute summary statistics over the entire taxonomy."""
        total = len(self.techniques)
        category_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        effectiveness_sum = 0
        mitre_ids: set = set()

        for t in self.techniques:
            category_counts[t.category] = category_counts.get(t.category, 0) + 1
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1
            effectiveness_sum += t.effectiveness_rating
            mitre_ids.add(t.mitre_atlas_id)

        avg_effectiveness = round(effectiveness_sum / total, 2) if total else 0.0

        return {
            "total_techniques": total,
            "categories": category_counts,
            "severity_distribution": severity_counts,
            "average_effectiveness_rating": avg_effectiveness,
            "unique_mitre_atlas_ids": sorted(mitre_ids),
            "top_5_risk": [
                {"id": t.id, "name": t.name, "risk_score": t.risk_score()}
                for t in self.top_risk(5)
            ],
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export_json(self, output_path: Optional[Path] = None, indent: int = 2) -> str:
        """Export full taxonomy to JSON. Returns the JSON string."""
        payload = {
            "schema_version": self.metadata.get("schema_version", "1.0.0"),
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "total_techniques": len(self.techniques),
            "techniques": [t.to_dict() for t in self.techniques],
        }
        json_str = json.dumps(payload, indent=indent, ensure_ascii=False)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_str, encoding="utf-8")
            print(f"[export] JSON written to {output_path}")
        return json_str

    def export_csv(self, output_path: Optional[Path] = None) -> str:
        """Export taxonomy to CSV. Returns the CSV string."""
        fieldnames = [
            "id", "name", "category", "subcategory", "severity",
            "effectiveness_rating", "risk_score", "mitre_atlas_id",
            "mitre_atlas_tactic", "mitre_atlas_technique",
            "first_documented", "tags", "affected_models",
        ]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for t in self.techniques:
            writer.writerow({
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "subcategory": t.subcategory,
                "severity": t.severity,
                "effectiveness_rating": t.effectiveness_rating,
                "risk_score": t.risk_score(),
                "mitre_atlas_id": t.mitre_atlas_id,
                "mitre_atlas_tactic": t.mitre_atlas_tactic,
                "mitre_atlas_technique": t.mitre_atlas_technique,
                "first_documented": t.first_documented,
                "tags": "; ".join(t.tags),
                "affected_models": "; ".join(t.affected_models),
            })
        csv_str = buf.getvalue()
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(csv_str, encoding="utf-8")
            print(f"[export] CSV written to {output_path}")
        return csv_str

    def export_markdown(self, output_path: Optional[Path] = None) -> str:
        """Export taxonomy as a Markdown table."""
        lines = [
            "# Jailbreak Taxonomy — Full Technique Table",
            f"_Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_",
            "",
            "| ID | Name | Category | Severity | Effectiveness | MITRE ID | Risk Score |",
            "|----|------|----------|----------|---------------|----------|------------|",
        ]
        for t in sorted(self.techniques, key=lambda x: x.risk_score(), reverse=True):
            lines.append(
                f"| {t.id} | {t.name} | {t.category} | {t.severity} "
                f"| {t.effectiveness_rating}/5 | {t.mitre_atlas_id} | {t.risk_score()} |"
            )
        md = "\n".join(lines)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(md, encoding="utf-8")
            print(f"[export] Markdown written to {output_path}")
        return md

    # ------------------------------------------------------------------
    # Rich display helpers
    # ------------------------------------------------------------------
    def print_table(self, techniques: Optional[List[JailbreakTechnique]] = None) -> None:
        techs = techniques or self.techniques
        if not techs:
            print("No techniques to display.")
            return

        if RICH_AVAILABLE:
            console = Console()
            table = Table(title="Jailbreak Technique Taxonomy", show_lines=True)
            table.add_column("ID", style="cyan", no_wrap=True)
            table.add_column("Name", style="bold white")
            table.add_column("Category", style="magenta")
            table.add_column("Severity", style="red")
            table.add_column("Eff.", justify="center")
            table.add_column("MITRE ID", style="yellow")
            table.add_column("Risk", justify="right", style="green")

            severity_colors = {
                "CRITICAL": "[bold red]CRITICAL[/]",
                "HIGH": "[red]HIGH[/]",
                "MEDIUM": "[yellow]MEDIUM[/]",
                "LOW": "[green]LOW[/]",
            }
            for t in sorted(techs, key=lambda x: x.risk_score(), reverse=True):
                table.add_row(
                    t.id,
                    t.name,
                    t.category,
                    severity_colors.get(t.severity, t.severity),
                    str(t.effectiveness_rating) + "/5",
                    t.mitre_atlas_id,
                    str(t.risk_score()),
                )
            console.print(table)
        else:
            # Fallback plain text
            header = f"{'ID':<9} {'Name':<40} {'Category':<30} {'Sev':<9} {'Eff':<5} {'MITRE':<15} {'Risk'}"
            print(header)
            print("-" * len(header))
            for t in sorted(techs, key=lambda x: x.risk_score(), reverse=True):
                print(
                    f"{t.id:<9} {t.name:<40} {t.category:<30} "
                    f"{t.severity:<9} {t.effectiveness_rating}/5  "
                    f"{t.mitre_atlas_id:<15} {t.risk_score()}"
                )

    def print_stats(self) -> None:
        stats = self.statistics()
        if RICH_AVAILABLE:
            console = Console()
            console.rule("[bold cyan]Taxonomy Statistics[/]")
            console.print(f"Total techniques: [bold]{stats['total_techniques']}[/]")
            console.print(f"Avg effectiveness: [bold]{stats['average_effectiveness_rating']}/5[/]")
            console.print(f"MITRE ATLAS IDs covered: {', '.join(stats['unique_mitre_atlas_ids'])}")

            sev_table = Table(title="Severity Distribution")
            sev_table.add_column("Severity")
            sev_table.add_column("Count", justify="right")
            for sev, count in sorted(stats["severity_distribution"].items(),
                                     key=lambda x: SEVERITY_ORDER.get(x[0], 0), reverse=True):
                sev_table.add_row(sev, str(count))
            console.print(sev_table)

            risk_table = Table(title="Top 5 Techniques by Risk Score")
            risk_table.add_column("ID")
            risk_table.add_column("Name")
            risk_table.add_column("Risk Score", justify="right")
            for entry in stats["top_5_risk"]:
                risk_table.add_row(entry["id"], entry["name"], str(entry["risk_score"]))
            console.print(risk_table)
        else:
            print(json.dumps(stats, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Jailbreak Taxonomy Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--taxonomy", default=str(DEFAULT_TAXONOMY_PATH),
                   help="Path to the taxonomy JSON file")
    p.add_argument("--list-all", action="store_true",
                   help="List all techniques")
    p.add_argument("--category", metavar="CAT",
                   help="Filter by category name")
    p.add_argument("--severity", metavar="SEV", choices=list(SEVERITY_ORDER),
                   help="Filter by severity level")
    p.add_argument("--tag", metavar="TAG",
                   help="Filter by tag")
    p.add_argument("--effectiveness", metavar="N", type=int,
                   help="Filter by minimum effectiveness rating (1-5)")
    p.add_argument("--mitre", metavar="ID",
                   help="Filter by MITRE ATLAS technique ID")
    p.add_argument("--search", metavar="QUERY",
                   help="Full-text search across name, description, tags")
    p.add_argument("--id", metavar="ID",
                   help="Show a single technique by ID")
    p.add_argument("--top-risk", metavar="N", type=int, default=0,
                   help="Show top N techniques by risk score")
    p.add_argument("--stats", action="store_true",
                   help="Show taxonomy statistics")
    p.add_argument("--export", choices=["json", "csv", "markdown"],
                   help="Export format")
    p.add_argument("--output", metavar="FILE",
                   help="Output file path for export")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    taxonomy = JailbreakTaxonomy(Path(args.taxonomy))

    if args.stats:
        taxonomy.print_stats()
        return

    if args.id:
        technique = taxonomy.get_by_id(args.id)
        if technique:
            print(json.dumps(technique.to_dict(), indent=2))
        else:
            print(f"Technique '{args.id}' not found.", file=sys.stderr)
            sys.exit(1)
        return

    if args.export:
        out = Path(args.output) if args.output else None
        if args.export == "json":
            result = taxonomy.export_json(out)
        elif args.export == "csv":
            result = taxonomy.export_csv(out)
        else:
            result = taxonomy.export_markdown(out)
        if not out:
            print(result)
        return

    # Filter and display
    results = taxonomy.techniques

    if args.list_all:
        taxonomy.print_table(results)
        return

    if args.category:
        results = taxonomy.filter_by_category(args.category)
    if args.severity:
        results = taxonomy.filter_by_severity(args.severity)
    if args.tag:
        results = taxonomy.filter_by_tag(args.tag)
    if args.effectiveness:
        results = taxonomy.filter_by_effectiveness(args.effectiveness)
    if args.mitre:
        results = taxonomy.filter_by_mitre_id(args.mitre)
    if args.search:
        results = taxonomy.search(args.search)
    if args.top_risk:
        results = taxonomy.top_risk(args.top_risk)

    if results or (args.category or args.severity or args.tag or
                   args.effectiveness or args.mitre or args.search or args.top_risk):
        taxonomy.print_table(results)
        print(f"\n{len(results)} technique(s) matched.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
