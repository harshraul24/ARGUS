"""ConfoundGuard — suppress indicators that carry no information in this corpus.

An indicator present in essentially all captures of *both* classes (for example a step
of the capture protocol itself) has zero discriminative information: scoring it measures
the protocol, not behaviour.

The rule is computed from the corpus, not hardcoded: any technique whose prevalence
exceeds `threshold` in both classes is marked a capture artifact. It is still reported to
the analyst, but excluded from the disposition, and the reason is recorded. Without a
report (the default) the guard is off.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ConfoundReport:
    artifact_techniques: set[str] = field(default_factory=set)
    prevalence: dict[str, dict[str, float]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"artifact_techniques": sorted(self.artifact_techniques),
                "prevalence": self.prevalence, "notes": self.notes}


def scan_corpus(data_dir: Path, threshold: float = 0.9) -> ConfoundReport:
    """Compute per-technique prevalence across attack and benign captures."""
    from argus.case import ground_truth, load_case
    from argus.reason.engine import Config, reason

    rep = ConfoundReport()
    cfg = Config(confound=None)          # scan with the guard disabled

    fired: dict[str, dict[str, int]] = {}
    totals = {"attack": 0, "benign": 0}

    for d in sorted(Path(data_dir).iterdir()):
        if not (d / "meta.json").exists():
            continue
        gt = ground_truth(d)
        cls = "attack" if gt["is_attack"] else "benign"
        totals[cls] += 1
        lc = load_case(d)
        dec = reason(lc.case_id, lc.claims, lc.health, cfg)
        for h in dec.hypotheses:
            if h.score <= 0:
                continue
            fired.setdefault(h.technique, {"attack": 0, "benign": 0})[cls] += 1

    for tech, counts in fired.items():
        pa = counts["attack"] / totals["attack"] if totals["attack"] else 0.0
        pb = counts["benign"] / totals["benign"] if totals["benign"] else 0.0
        rep.prevalence[tech] = {"attack": round(pa, 3), "benign": round(pb, 3)}
        if pa >= threshold and pb >= threshold:
            rep.artifact_techniques.add(tech)
            rep.notes.append(
                f"{tech}: fires in {pa:.0%} of attack and {pb:.0%} of benign captures — "
                f"no discriminative information; treated as a capture artifact")

    return rep


DEFAULT_PATH = Path(__file__).parent / "confound_report.json"


def save(rep: ConfoundReport, path: Path = DEFAULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rep.to_dict(), indent=2))


def load(path: Path = DEFAULT_PATH) -> ConfoundReport:
    if not Path(path).exists():
        return ConfoundReport()
    d = json.loads(Path(path).read_text())
    return ConfoundReport(artifact_techniques=set(d.get("artifact_techniques", [])),
                          prevalence=d.get("prevalence", {}),
                          notes=d.get("notes", []))
