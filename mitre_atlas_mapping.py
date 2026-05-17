"""
mitre_atlas_mapping.py
Jailbreak-as-a-Service Threat Landscape
-----------------------------------------
Maps jailbreak techniques to MITRE ATLAS (Adversarial Threat Landscape for
Artificial-Intelligence Systems) v2.1 tactics and techniques.

Provides:
  - Full MITRE ATLAS tactic/technique reference data
  - Mapping lookups between JBT technique IDs and ATLAS nodes
  - Kill-chain visualisation per technique
  - Attack path analysis across the ATLAS matrix
  - Export to ATT&CK Navigator-compatible JSON layer

Usage:
    python mitre_atlas_mapping.py --list-tactics
    python mitre_atlas_mapping.py --list-techniques
    python mitre_atlas_mapping.py --map-jailbreak JBT-003
    python mitre_atlas_mapping.py --coverage-report
    python mitre_atlas_mapping.py --export-navigator --output results/navigator_layer.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from jailbreak_taxonomy import JailbreakTaxonomy, JailbreakTechnique

# ---------------------------------------------------------------------------
# MITRE ATLAS Reference Data (v2.1)
# Source: https://atlas.mitre.org
# ---------------------------------------------------------------------------

ATLAS_TACTICS: Dict[str, Dict[str, str]] = {
    "AML.TA0001": {
        "name": "Reconnaissance",
        "description": "Gather information about the ML system and pipeline to enable further attacks.",
    },
    "AML.TA0002": {
        "name": "Resource Development",
        "description": "Establish resources (infrastructure, accounts, capabilities) to support operations.",
    },
    "AML.TA0003": {
        "name": "ML Attack Staging",
        "description": "Prepare adversarial data, models, or payloads prior to the main attack.",
    },
    "AML.TA0004": {
        "name": "ML Model Access",
        "description": "Obtain access to ML models through APIs, open-source releases, or supply chains.",
    },
    "AML.TA0005": {
        "name": "Exfiltration",
        "description": "Steal model weights, training data, hyperparameters, or sensitive outputs.",
    },
    "AML.TA0006": {
        "name": "Impact",
        "description": "Manipulate, interrupt, or destroy systems and data to achieve adversarial goals.",
    },
}

ATLAS_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "AML.T0020": {
        "name": "Poison Training Data",
        "tactic_id": "AML.TA0003",
        "tactic_name": "ML Attack Staging",
        "description": "Inject malicious examples into the training dataset to influence model behaviour at inference time.",
        "url": "https://atlas.mitre.org/techniques/AML.T0020/",
        "subtechniques": ["AML.T0020.001", "AML.T0020.002"],
    },
    "AML.T0043": {
        "name": "Craft Adversarial Data",
        "tactic_id": "AML.TA0003",
        "tactic_name": "ML Attack Staging",
        "description": "Create inputs designed to cause model misclassification or unsafe outputs.",
        "url": "https://atlas.mitre.org/techniques/AML.T0043/",
        "subtechniques": [],
    },
    "AML.T0054": {
        "name": "LLM Prompt Injection",
        "tactic_id": "AML.TA0004",
        "tactic_name": "ML Model Access",
        "description": "Craft prompts that override or manipulate LLM instructions, bypassing safety measures.",
        "url": "https://atlas.mitre.org/techniques/AML.T0054/",
        "subtechniques": ["AML.T0054.001", "AML.T0054.002"],
    },
    "AML.T0054.001": {
        "name": "LLM Prompt Injection - Multi-Turn",
        "tactic_id": "AML.TA0004",
        "tactic_name": "ML Model Access",
        "description": "Exploit multi-turn conversation context to gradually escalate to unsafe outputs.",
        "url": "https://atlas.mitre.org/techniques/AML.T0054.001/",
        "subtechniques": [],
        "parent": "AML.T0054",
    },
    "AML.T0054.002": {
        "name": "Indirect Prompt Injection",
        "tactic_id": "AML.TA0003",
        "tactic_name": "ML Attack Staging",
        "description": "Embed malicious instructions in third-party content consumed by an LLM agent.",
        "url": "https://atlas.mitre.org/techniques/AML.T0054.002/",
        "subtechniques": [],
        "parent": "AML.T0054",
    },
    "AML.T0056": {
        "name": "Exfiltration via ML Inference API",
        "tactic_id": "AML.TA0005",
        "tactic_name": "Exfiltration",
        "description": "Use model inference endpoints to extract training data, model parameters, or system prompts.",
        "url": "https://atlas.mitre.org/techniques/AML.T0056/",
        "subtechniques": [],
    },
    "AML.T0040": {
        "name": "ML Supply Chain Compromise",
        "tactic_id": "AML.TA0003",
        "tactic_name": "ML Attack Staging",
        "description": "Compromise ML libraries, frameworks, pre-trained models, or data pipelines used by the target.",
        "url": "https://atlas.mitre.org/techniques/AML.T0040/",
        "subtechniques": [],
    },
    "AML.T0044": {
        "name": "Full ML Model Access",
        "tactic_id": "AML.TA0004",
        "tactic_name": "ML Model Access",
        "description": "Obtain complete white-box access to the model including weights and architecture.",
        "url": "https://atlas.mitre.org/techniques/AML.T0044/",
        "subtechniques": [],
    },
    "AML.T0048": {
        "name": "LLM Plugin Compromise",
        "tactic_id": "AML.TA0006",
        "tactic_name": "Impact",
        "description": "Exploit LLM plugins or tools to achieve arbitrary code execution or privilege escalation.",
        "url": "https://atlas.mitre.org/techniques/AML.T0048/",
        "subtechniques": [],
    },
}

# ---------------------------------------------------------------------------
# Kill Chain mapping: jailbreak category -> typical ATLAS kill-chain steps
# ---------------------------------------------------------------------------

KILL_CHAIN_PATHS: Dict[str, List[str]] = {
    "Role Playing / Persona": [
        "AML.TA0004 (ML Model Access)",
        "AML.T0054 (LLM Prompt Injection)",
        "Impact: Unsafe content generation",
    ],
    "Context Manipulation": [
        "AML.TA0003 (ML Attack Staging)",
        "AML.T0054.001 (Multi-Turn Injection)",
        "Impact: Gradual safety bypass",
    ],
    "Prompt Injection": [
        "AML.TA0003 (ML Attack Staging)",
        "AML.T0054.002 (Indirect Prompt Injection)",
        "AML.TA0005 (Exfiltration) or AML.TA0006 (Impact)",
    ],
    "Encoding and Obfuscation": [
        "AML.TA0003 (ML Attack Staging)",
        "AML.T0043 (Craft Adversarial Data)",
        "AML.T0054 (LLM Prompt Injection)",
        "Impact: Filter bypass",
    ],
    "Adversarial Inputs": [
        "AML.TA0003 (ML Attack Staging)",
        "AML.T0043 (Craft Adversarial Data)",
        "AML.TA0004 (ML Model Access)",
        "Impact: Universal jailbreak",
    ],
    "Supply Chain Attack": [
        "AML.TA0002 (Resource Development)",
        "AML.T0020 (Poison Training Data)",
        "AML.T0040 (ML Supply Chain Compromise)",
        "AML.TA0006 (Impact): Persistent backdoor",
    ],
}

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class AtlasMapping:
    """Full ATLAS mapping for a single jailbreak technique."""
    jailbreak_id: str
    jailbreak_name: str
    jailbreak_category: str
    atlas_id: str
    atlas_technique_name: str
    atlas_tactic_id: str
    atlas_tactic_name: str
    atlas_url: str
    kill_chain_path: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "jailbreak_id": self.jailbreak_id,
            "jailbreak_name": self.jailbreak_name,
            "jailbreak_category": self.jailbreak_category,
            "atlas_mapping": {
                "id": self.atlas_id,
                "technique": self.atlas_technique_name,
                "tactic_id": self.atlas_tactic_id,
                "tactic": self.atlas_tactic_name,
                "url": self.atlas_url,
            },
            "kill_chain_path": self.kill_chain_path,
            "mitigations": self.mitigations,
        }


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class MitreAtlasMapper:
    """
    Maps the jailbreak taxonomy to MITRE ATLAS.
    Provides coverage analysis, kill-chain visualisation, and Navigator export.
    """

    def __init__(self, taxonomy: JailbreakTaxonomy) -> None:
        self.taxonomy = taxonomy
        self.techniques = ATLAS_TECHNIQUES
        self.tactics = ATLAS_TACTICS
        self._mappings: Optional[List[AtlasMapping]] = None

    def _build_mappings(self) -> List[AtlasMapping]:
        """Build AtlasMapping objects for every technique in the taxonomy."""
        mappings = []
        for jbt in self.taxonomy.techniques:
            atlas_id = jbt.mitre_atlas_id
            atlas_tech = self.techniques.get(atlas_id, {})
            tactic_id = atlas_tech.get("tactic_id", "UNKNOWN")
            tactic = self.tactics.get(tactic_id, {})

            kill_chain = KILL_CHAIN_PATHS.get(jbt.category, [
                f"{tactic_id} ({tactic.get('name', 'Unknown Tactic')})",
                f"{atlas_id} ({atlas_tech.get('name', 'Unknown Technique')})",
                "Impact: Undefined",
            ])

            mappings.append(AtlasMapping(
                jailbreak_id=jbt.id,
                jailbreak_name=jbt.name,
                jailbreak_category=jbt.category,
                atlas_id=atlas_id,
                atlas_technique_name=atlas_tech.get("name", "Unknown"),
                atlas_tactic_id=tactic_id,
                atlas_tactic_name=tactic.get("name", "Unknown"),
                atlas_url=atlas_tech.get("url", f"https://atlas.mitre.org/techniques/{atlas_id}/"),
                kill_chain_path=kill_chain,
                mitigations=jbt.defense_recommendations,
            ))
        return mappings

    @property
    def mappings(self) -> List[AtlasMapping]:
        if self._mappings is None:
            self._mappings = self._build_mappings()
        return self._mappings

    def get_mapping_for_jailbreak(self, jbt_id: str) -> Optional[AtlasMapping]:
        for m in self.mappings:
            if m.jailbreak_id.upper() == jbt_id.upper():
                return m
        return None

    def coverage_by_tactic(self) -> Dict[str, List[str]]:
        """Return a dict: tactic_name -> [jailbreak IDs] covered."""
        result: Dict[str, List[str]] = {}
        for m in self.mappings:
            key = f"{m.atlas_tactic_id}: {m.atlas_tactic_name}"
            result.setdefault(key, []).append(m.jailbreak_id)
        return result

    def coverage_by_technique(self) -> Dict[str, List[str]]:
        """Return a dict: atlas_technique_id -> [jailbreak IDs] covered."""
        result: Dict[str, List[str]] = {}
        for m in self.mappings:
            key = f"{m.atlas_id}: {m.atlas_technique_name}"
            result.setdefault(key, []).append(m.jailbreak_id)
        return result

    def uncovered_techniques(self) -> List[str]:
        """List ATLAS techniques that have no jailbreak mapping."""
        covered = {m.atlas_id for m in self.mappings}
        return [tid for tid in self.techniques if tid not in covered]

    # ------------------------------------------------------------------
    # ATT&CK Navigator export
    # ------------------------------------------------------------------
    def export_navigator_layer(self, output_path: Optional[Path] = None) -> str:
        """
        Generate an ATT&CK Navigator-compatible layer JSON.
        Load at https://mitre-attack.github.io/attack-navigator/
        (select ATLAS matrix domain).
        """
        # Compute score per technique (number of jailbreak techniques mapped)
        coverage = self.coverage_by_technique()
        technique_scores: Dict[str, int] = {}
        for key, jbt_ids in coverage.items():
            atlas_id = key.split(":")[0].strip()
            technique_scores[atlas_id] = len(jbt_ids)

        max_score = max(technique_scores.values(), default=1)

        techniques_layer = []
        for atlas_id, score in technique_scores.items():
            techniques_layer.append({
                "techniqueID": atlas_id,
                "score": score,
                "color": "",
                "comment": f"Covered by {score} jailbreak technique(s)",
                "enabled": True,
                "metadata": [],
                "showSubtechniques": True,
            })

        layer = {
            "name": "Jailbreak Threat Landscape - MITRE ATLAS Coverage",
            "versions": {
                "attack": "14",
                "navigator": "4.9",
                "layer": "4.5"
            },
            "domain": "mitre-atlas",
            "description": (
                "Coverage layer generated by jailbreak-threat-landscape project. "
                "Score = number of documented jailbreak techniques per ATLAS node."
            ),
            "filters": {"platforms": ["LLM", "ML Model"]},
            "sorting": 3,
            "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques_layer,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": max_score,
            },
            "legendItems": [
                {"label": "No coverage", "color": "#ffffff"},
                {"label": "High coverage", "color": "#ff6666"},
            ],
        }
        json_str = json.dumps(layer, indent=2)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_str, encoding="utf-8")
            print(f"[export] Navigator layer written to {output_path}")
        return json_str

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------
    def print_mapping(self, mapping: AtlasMapping) -> None:
        if RICH_AVAILABLE:
            console = Console()
            console.rule(f"[bold cyan]{mapping.jailbreak_id}: {mapping.jailbreak_name}[/]")
            console.print(f"  Category:  [magenta]{mapping.jailbreak_category}[/]")
            console.print(f"  ATLAS ID:  [yellow]{mapping.atlas_id}[/]")
            console.print(f"  Technique: {mapping.atlas_technique_name}")
            console.print(f"  Tactic:    {mapping.atlas_tactic_id} — {mapping.atlas_tactic_name}")
            console.print(f"  URL:       [link={mapping.atlas_url}]{mapping.atlas_url}[/link]")
            console.print()

            tree = Tree("[bold]Kill Chain[/]")
            for i, step in enumerate(mapping.kill_chain_path, 1):
                tree.add(f"[{i}] {step}")
            console.print(tree)

            if mapping.mitigations:
                console.print("\n[bold]Mitigations:[/]")
                for m in mapping.mitigations:
                    console.print(f"  • {m}")
        else:
            print(json.dumps(mapping.to_dict(), indent=2))

    def print_coverage_report(self) -> None:
        coverage = self.coverage_by_technique()
        uncovered = self.uncovered_techniques()

        if RICH_AVAILABLE:
            console = Console()
            console.rule("[bold cyan]MITRE ATLAS Coverage Report[/]")

            table = Table(title="Techniques Covered by Jailbreak Taxonomy", show_lines=True)
            table.add_column("ATLAS ID", style="yellow")
            table.add_column("Technique Name")
            table.add_column("Jailbreak IDs", style="cyan")
            table.add_column("Count", justify="right", style="green")

            for key, jbt_ids in sorted(coverage.items()):
                atlas_id, technique_name = key.split(":", 1)
                table.add_row(
                    atlas_id.strip(),
                    technique_name.strip(),
                    ", ".join(jbt_ids),
                    str(len(jbt_ids)),
                )
            console.print(table)

            if uncovered:
                console.print(f"\n[yellow]Uncovered ATLAS techniques ({len(uncovered)}):[/]")
                for tid in uncovered:
                    name = self.techniques.get(tid, {}).get("name", "Unknown")
                    console.print(f"  • {tid}: {name}")
            else:
                console.print("\n[green]All referenced ATLAS techniques are covered.[/]")
        else:
            print("Coverage by technique:")
            for key, jbt_ids in sorted(coverage.items()):
                print(f"  {key}: {', '.join(jbt_ids)}")
            if uncovered:
                print(f"\nUncovered: {', '.join(uncovered)}")

    def print_tactics_table(self) -> None:
        if RICH_AVAILABLE:
            console = Console()
            table = Table(title="MITRE ATLAS Tactics Reference")
            table.add_column("Tactic ID", style="yellow")
            table.add_column("Name", style="bold")
            table.add_column("Description")
            for tid, tdata in self.tactics.items():
                table.add_row(tid, tdata["name"], tdata["description"])
            console.print(table)
        else:
            for tid, tdata in self.tactics.items():
                print(f"{tid}: {tdata['name']} — {tdata['description']}")

    def print_techniques_table(self) -> None:
        if RICH_AVAILABLE:
            console = Console()
            table = Table(title="MITRE ATLAS Techniques Reference")
            table.add_column("Technique ID", style="yellow")
            table.add_column("Name", style="bold")
            table.add_column("Tactic", style="magenta")
            table.add_column("URL", style="cyan")
            for tid, tdata in self.techniques.items():
                table.add_row(
                    tid,
                    tdata["name"],
                    tdata.get("tactic_name", ""),
                    tdata.get("url", ""),
                )
            console.print(table)
        else:
            for tid, tdata in self.techniques.items():
                print(f"{tid}: {tdata['name']} [{tdata.get('tactic_name')}]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="MITRE ATLAS Mapper for Jailbreak Taxonomy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--taxonomy", default="techniques/jailbreak_techniques.json",
                   help="Path to taxonomy JSON")
    p.add_argument("--list-tactics", action="store_true",
                   help="List all MITRE ATLAS tactics")
    p.add_argument("--list-techniques", action="store_true",
                   help="List all MITRE ATLAS techniques")
    p.add_argument("--map-jailbreak", metavar="JBT_ID",
                   help="Show ATLAS mapping for a specific jailbreak technique (e.g. JBT-003)")
    p.add_argument("--coverage-report", action="store_true",
                   help="Show coverage report: which ATLAS nodes the taxonomy covers")
    p.add_argument("--export-navigator", action="store_true",
                   help="Export ATT&CK Navigator layer JSON")
    p.add_argument("--output", metavar="FILE",
                   help="Output file path (for --export-navigator)")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    taxonomy = JailbreakTaxonomy(Path(args.taxonomy))
    mapper = MitreAtlasMapper(taxonomy)

    if args.list_tactics:
        mapper.print_tactics_table()
        return

    if args.list_techniques:
        mapper.print_techniques_table()
        return

    if args.map_jailbreak:
        mapping = mapper.get_mapping_for_jailbreak(args.map_jailbreak)
        if mapping:
            mapper.print_mapping(mapping)
        else:
            print(f"No mapping found for '{args.map_jailbreak}'", file=sys.stderr)
            sys.exit(1)
        return

    if args.coverage_report:
        mapper.print_coverage_report()
        return

    if args.export_navigator:
        out = Path(args.output) if args.output else None
        result = mapper.export_navigator_layer(out)
        if not out:
            print(result)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
