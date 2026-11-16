#!/usr/bin/env python3
"""GuardDuty finding-type coverage -> MITRE ATT&CK Navigator layer."""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ATTACK_VERSION = "20"
NAVIGATOR_VERSION = "4.9.5"
LAYER_VERSION = "4.5"


def load_mapping(path: str):
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return data["findings"]


def load_covered(path: str | None, all_types):
    if not path:
        return set(all_types)
    covered = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            covered.add(line)
    return covered


def build_layer(findings, covered, name):
    agg = defaultdict(lambda: {"count": 0, "findings": []})
    for f in findings:
        ft = f["finding_type"]
        if ft not in covered:
            continue
        key = (f["technique_id"], f["tactic"])
        agg[key]["count"] += 1
        agg[key]["findings"].append(ft)

    max_score = max((v["count"] for v in agg.values()), default=1)

    techniques = []
    for (tech, tactic), v in sorted(agg.items()):
        techniques.append(
            {
                "techniqueID": tech,
                "tactic": tactic,
                "score": v["count"],
                "enabled": True,
                "comment": "GuardDuty: " + ", ".join(sorted(v["findings"])),
                "metadata": [],
            }
        )

    return {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": "GuardDuty detection coverage mapped to MITRE ATT&CK.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#d7e8ff", "#1f6fd6", "#0b3b78"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#2b2b2b",
        "selectTechniquesAcrossTactics": True,
        "hideDisabled": False,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mapping", default="mappings/guardduty_attack_mapping.yaml")
    ap.add_argument("--covered", help="enabled finding types file (default: all)")
    ap.add_argument("--name", default="GuardDuty ATT&CK coverage")
    ap.add_argument("--out", default="output/guardduty_coverage.layer.json")
    args = ap.parse_args()

    findings = load_mapping(args.mapping)
    all_types = [f["finding_type"] for f in findings]
    covered = load_covered(args.covered, all_types)

    layer = build_layer(findings, covered, args.name)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")

    tactic_counts = Counter(t["tactic"] for t in layer["techniques"])
    covered_n = sum(1 for t in all_types if t in covered)
    print(f"Wrote {out}")
    print(f"  finding types in mapping : {len(all_types)}")
    print(f"  covered finding types    : {covered_n}")
    print(f"  techniques lit           : {len(layer['techniques'])}")
    print(f"  tactics covered          : {len(tactic_counts)} ({', '.join(sorted(tactic_counts))})")


if __name__ == "__main__":
    main()
