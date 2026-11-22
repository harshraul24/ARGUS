"""Empirical observability — O(sensor, claim_type) measured, not asserted.

An absence of evidence weighs only as much as the sensor's measured habit of emitting that
evidence. Measure how often each sensor actually emits each claim type across a corpus:

    O(authlog, logon_success)   = 8/8 captures  ->  its absence is a strong signal
    O(auditd,  file_write)      = 2/8 captures  ->  its absence is a weak signal

An absence from a sensor that rarely emits the event is weak counter-evidence. An
absence from a sensor that always emits it is strong. No causal story required.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path(__file__).parent / "observability_model.json"


@dataclass
class ObservabilityModel:
    """Fraction of captures in which a sensor emitted a given claim type."""
    rates: dict[str, float] = field(default_factory=dict)   # "sensor:claim_type" -> 0..1
    n_captures: int = 0
    notes: list[str] = field(default_factory=list)

    def rate(self, sensor_id: str, claim_type: str, default: float = 1.0) -> float:
        return self.rates.get(f"{sensor_id}:{claim_type}", default)

    def to_dict(self) -> dict:
        return {"rates": self.rates, "n_captures": self.n_captures, "notes": self.notes}


# Which sensor each claim type comes from.
SENSOR_OF = {
    "logon_failure": "authlog", "logon_success": "authlog",
    "privileged_command": "authlog", "session_opened": "authlog",
    "remote_access_session": "zeek", "network_connection": "zeek", "dns_query": "zeek",
    "process_create": "auditd", "host_network_connection": "auditd",
    "file_read": "auditd", "file_write": "auditd", "file_create": "auditd",
    "file_delete": "auditd", "file_rename": "auditd",
}


def scan_corpus(data_dir: Path) -> ObservabilityModel:
    from argus.case import load_case

    model = ObservabilityModel()
    seen: dict[str, int] = {}
    n = 0

    for d in sorted(Path(data_dir).iterdir()):
        if not (d / "meta.json").exists():
            continue
        n += 1
        lc = load_case(d)
        types = {c.claim_type for c in lc.claims}
        for ct in set(SENSOR_OF):
            key = f"{SENSOR_OF[ct]}:{ct}"
            seen.setdefault(key, 0)
            if ct in types:
                seen[key] += 1

    model.n_captures = n
    model.rates = {k: round(v / n, 3) for k, v in seen.items()} if n else {}
    for k, r in sorted(model.rates.items(), key=lambda x: x[1]):
        if r <= 0.5:
            model.notes.append(
                f"{k}: emitted in {r:.0%} of captures — absence is weak counter-evidence")
    return model


def save(model: ObservabilityModel, path: Path = DEFAULT_PATH) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(model.to_dict(), indent=2))


def load(path: Path = DEFAULT_PATH) -> ObservabilityModel:
    if not Path(path).exists():
        return ObservabilityModel()
    d = json.loads(Path(path).read_text())
    return ObservabilityModel(rates=d.get("rates", {}),
                              n_captures=d.get("n_captures", 0),
                              notes=d.get("notes", []))
