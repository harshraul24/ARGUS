"""Process lineage, episodes, the kill chain and sensor contracts on REAL lab windows (run1).

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

from argus.collectors.events import events_health
from argus.reason.engine import Config, reason
from argus.reason.lineage import ProcessGraph, user_writable

from lab_data import AGENT_WINDOW, STEPS_WINDOW, case, needs_lab


def test_folders_decide_user_writable_not_names():
    assert user_writable("/home/www/splunkd") is True
    assert user_writable("/tmp/x") is True and user_writable("/dev/shm/y") is True
    assert user_writable("/usr/bin/dash") is False and user_writable("/usr/sbin/sshd") is False
    assert user_writable("splunkd") is None                                # not a path


@needs_lab
def test_the_graph_is_rebuilt_from_claims_and_reads_where_the_agent_runs():
    g = ProcessGraph.from_claims(case(AGENT_WINDOW).claims)
    agent = next(k for k, img in g.image.items() if img == "splunkd")
    assert g.writable(agent) is True                                        # it runs from the user's home
    kids = {g.image.get(k) for k in g.children[agent]}
    assert kids == {"dash"} and all(g.writable(k) is False for k in g.children[agent])


@needs_lab
def test_a_hub_is_decided_by_its_children_not_its_name():
    g = ProcessGraph.from_claims(case("run1_web01_1300").claims)
    hubs = {g.image.get(k) for k in g.parent if g.is_hub(k)}
    assert {"apt-get", "dpkg"} <= hubs                                      # package installs fan out
    agent_g = ProcessGraph.from_claims(case(AGENT_WINDOW).claims)
    assert not any(agent_g.is_hub(k) for k, i in agent_g.image.items() if i == "splunkd")


@needs_lab
def test_the_kill_chain_needs_a_linking_non_hub_root_when_lineage_exists():
    """In this benign window (a package install under the login shell) the stages fire in
    unrelated subtrees: window-wide they fuse into a kill chain, linked they do not."""
    lc = case("run1_web01_1300")
    fired = lambda cfg: [h.technique for h in reason(lc.case_id, lc.claims, lc.health, cfg).hypotheses
                         if h.score > 0]
    assert "KILLCHAIN" in fired(Config(enable_lineage=False))
    assert "KILLCHAIN" not in fired(Config())


@needs_lab
def test_a_login_shell_is_a_hub_over_its_recorded_life():
    """13:30 on web01: the login shell that started both the agent (12:52) and the benign
    script launches few programs in this window, but many over its life. It is a hub, so
    the agent's steps and the script's activity are not fused into one kill chain."""
    lc = case(STEPS_WINDOW)
    g = ProcessGraph.from_claims(lc.claims)
    shell = next(k for k in g.parent if g.parent[k] is None and k.endswith("@pre")
                 and "splunkd" in g.life_children.get(k, set()))
    assert len(g.child_images(shell) - {"?"}) < 4 <= len(g.life_children[shell])
    assert g.is_hub(shell)
    d = reason(lc.case_id, lc.claims, lc.health, Config())
    assert "KILLCHAIN" not in [h.technique for h in d.hypotheses if h.score > 0]


@needs_lab
def test_an_episode_is_reported_apart_from_the_evidence():
    lc = case("run1_ws-fin01_1330")
    d = reason(lc.case_id, lc.claims, lc.health, Config())
    kc = next(h for h in d.hypotheses if h.technique == "KILLCHAIN")
    ep = d.episodes[0]
    assert len(ep["stages"]) >= 2 and set(kc.support) <= set(ep["claim_ids"])


@needs_lab
def test_a_contracted_type_the_sensor_never_emitted_is_a_blind_spot_even_when_benign():
    """run1's auditd loaded the connect rule. Drop this window's connect events and the
    absence is reported as blindness, never read as 'no connection happened'."""
    lc = case("run1_web01_1200")
    claims = [c for c in lc.claims if c.claim_type != "host_network_connection"]
    health = {"auditd": events_health(claims, lc.meta["sensor_contract"])}
    assert health["auditd"].blind_to == ["host_network_connection"]
    d = reason(lc.case_id, claims, health, Config())
    assert any("host_network_connection" in b for b in d.blind_spots)
