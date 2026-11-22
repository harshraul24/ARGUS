# S3 on Linux — rules written by an LLM from novel lab episodes, judged without labels

Generated 2026-10-08T03:38:25 by `tools/rules_induce.py`. ARGUS freeze `ARGUS_FREEZE_2026-10-08-a2.json`: **matches**.

Model `gpt-oss:120b-cloud` (ollama), temperature 0, seed 7. Design operations only (run1; 20 windows on 4 hosts). Test operations were not loaded. Novelty and C4 limit 25% of the host's other windows; at most 2 repair rounds. C5 promotes only on agreement from a non-LLM source: a hand-written tactic primitive, or one of 0 quiet Sigma rules (of 89 rated medium or above), or analyst approval (simulated from design labels (F8); 20 promoted, 2 retired).

Model calls: 57 (54 live, 3 from cache), 664.5 s of model time, ~115,966 tokens in, ~15,352 out.

**Library:** {'candidate': 0, 'shadow': 0, 'active': 20, 'retired': 5, 'rejected': 17}. Attempts by round: {0: 27, 1: 12, 2: 3}. Rejections by first failed check: {'repaired': 14, 'C4_rare_history': 3}. C2 causes: {'wrong_field': 1, 'not_observed': 4, 'jointly_unsatisfied': 4, 'partial': 1}.

## Selected sets on the design operations (labels used only here)

Design data, not a result: the model saw these windows. The test operations are scored once, after the final freeze (LAB_EVAL_PLAN.md §6).

| set | rules | attack windows | benign windows | event precision | attack steps |
|---|---|---|---|---|---|
| C1–C3 survivors (after repair) | 28 | 8/8 | 12/12 | 0.2643 | 28/36 |
| C1–C4 (shadow + active) | 25 | 8/8 | 9/12 | 0.5867 | 28/36 |
| C1–C5 active (non-LLM confirmation) | 20 | 8/8 | 0/12 | 1.0 | 28/36 |
| C1–C5 if any source promoted | 3 | 4/8 | 0/12 | 1.0 | 4/36 |
| hand-written tactic primitives (C5 source) | 5 | 8/8 | 8/12 | 0.011 | 12/36 |
| Sigma >= medium, quiet (C5 source) | 0 | 0/8 | 0/12 | None | 0/36 |
| hand-written + C1–C5 active | 25 | 8/8 | 8/12 | 0.0374 | 28/36 |

## Episodes the model was shown

| episode | root | novel launches | processes | prompt chars | rules written | calls |
|---|---|---|---|---|---|---|
| `run1_app01_1200` | systemctl | 8 | 8 | 1,149 | 0 | 1 |
| `run1_app01_1200` | dash | 3 | 2 | 322 | 0 | 1 |
| `run1_app01_1200` | generate | 2 | 2 | 345 | 0 | 1 |
| `run1_app01_1230` | splunkd | 5 | 6 | 850 | 6 | 2 |
| `run1_app01_1300` | dpkg | 22 | 20 | 3,391 | 0 | 1 |
| `run1_app01_1300` | dash | 8 | 8 | 1,134 | 0 | 1 |
| `run1_app01_1300` | dash | 8 | 8 | 1,134 | 0 | 1 |
| `run1_app01_1330` | dash | 3 | 3 | 384 | 1 | 1 |
| `run1_app01_1330` | dash | 2 | 2 | 302 | 1 | 1 |
| `run1_app01_1330` | dash | 2 | 2 | 346 | 2 | 2 |
| `run1_web01_1200` | systemctl | 8 | 8 | 1,149 | 0 | 1 |
| `run1_web01_1200` | systemctl | 8 | 8 | 1,149 | 0 | 1 |
| `run1_web01_1200` | dash | 3 | 2 | 322 | 0 | 1 |
| `run1_web01_1230` | splunkd | 5 | 6 | 850 | 4 | 2 |
| `run1_web01_1300` | dpkg | 22 | 20 | 3,391 | 0 | 1 |
| `run1_web01_1300` | dash | 8 | 8 | 1,134 | 0 | 1 |
| `run1_web01_1300` | dash | 8 | 8 | 1,134 | 0 | 1 |
| `run1_web01_1330` | dash | 3 | 3 | 384 | 2 | 2 |
| `run1_web01_1330` | dash | 2 | 2 | 302 | 1 | 1 |
| `run1_web01_1330` | dash | 2 | 2 | 346 | 1 | 1 |
| `run1_web01_1400` | sshd | 6 | 6 | 1,283 | 0 | 1 |
| `run1_web01_1400` | sshd | 6 | 6 | 1,283 | 0 | 1 |
| `run1_web01_1400` | sshd | 6 | 6 | 1,283 | 0 | 1 |
| `run1_ws-dev01_1200` | systemctl | 8 | 8 | 1,149 | 0 | 1 |
| `run1_ws-dev01_1200` | systemctl | 8 | 8 | 1,149 | 0 | 1 |
| `run1_ws-dev01_1200` | dash | 3 | 2 | 322 | 0 | 1 |
| `run1_ws-dev01_1230` | splunkd | 5 | 6 | 850 | 5 | 2 |
| `run1_ws-dev01_1300` | dpkg | 22 | 20 | 3,391 | 0 | 1 |
| `run1_ws-dev01_1300` | dash | 8 | 8 | 1,134 | 1 | 1 |
| `run1_ws-dev01_1300` | dash | 8 | 8 | 1,134 | 0 | 1 |
| `run1_ws-dev01_1330` | dash | 3 | 3 | 384 | 1 | 1 |
| `run1_ws-dev01_1330` | dash | 2 | 2 | 302 | 3 | 2 |
| `run1_ws-dev01_1330` | dash | 2 | 2 | 346 | 3 | 3 |
| `run1_ws-dev01_1400` | sshd | 6 | 6 | 1,283 | 0 | 1 |
| `run1_ws-dev01_1400` | bash | 2 | 2 | 430 | 1 | 1 |
| `run1_ws-fin01_1200` | dash | 47 | 68 | 5,097 | 0 | 1 |
| `run1_ws-fin01_1200` | perl | 23 | 21 | 3,493 | 0 | 1 |
| `run1_ws-fin01_1200` | dash | 16 | 14 | 2,297 | 1 | 1 |
| `run1_ws-fin01_1230` | splunkd | 5 | 6 | 850 | 5 | 3 |
| `run1_ws-fin01_1300` | dpkg | 22 | 20 | 3,391 | 0 | 1 |
| `run1_ws-fin01_1300` | dash | 9 | 9 | 1,250 | 0 | 1 |
| `run1_ws-fin01_1300` | dash | 9 | 9 | 1,250 | 0 | 1 |
| `run1_ws-fin01_1330` | dash | 3 | 3 | 384 | 3 | 3 |
| `run1_ws-fin01_1330` | dash | 2 | 2 | 302 | 0 | 1 |
| `run1_ws-fin01_1330` | dash | 2 | 2 | 346 | 1 | 1 |

## Every rule

| rule | status | reason | grade: attack · benign · precision | select |
|---|---|---|---|---|
| `llm.clear-bash-history-6f2c1d.b1bd756a50.r1` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"contains_any": ["bash_history"]}}` |
| `llm.clear-bash-history.f07f113ed0` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"contains_any": ["bash_history", "unset"]}}` |
| `llm.credential-dump-etc-master-passwd.60d65985b1.r1` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"contains_any": ["/etc/master.passwd"]}}` |
| `llm.credential-dump-etc-passwd.33e7af8567` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"any_of": [{"claim_type": "process_create", "facts.image": ["sudo"], "facts.command": {"contains_any": ["cat"]}}, {"claim_type": "file_read", "facts.file_path": {"contains_any": ["/etc/master.passwd"]}}]}` |
| `llm.credential-dump-master-passwd.a769aceab0` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"all_of": [{"contains_any": ["sudo"]}, {"contains_any": ["cat"]}, {"contains_any": ["master.passwd"]}]}}` |
| `llm.llm-clear-bash-history-547eba2a21.f68ca72a21.r1` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.image": ["dash"], "facts.command": {"contains_any": ["HISTFILE", "bash_history"]}}` |
| `llm.llm-credential-dump-passwd-414cfd5de7.0d5af25de7.r1` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.image": {"in": ["sh", "dash", "bash", "zsh"]}, "facts.command": {"all_of": [{"contains_any": ["passwd"]}, {"contains_any": ["/tmp/"]}]}}` |
| `llm.llm-discovery-from-user-writable-ancestor-e333f0.b528532a21.r1` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "lineage.ancestor_user_writable": {"truthy": true}, "facts.command": {"contains_any": ["whoami"]}}` |
| `llm.llm-llm-credential-dump-master-passwd-b0f086460c.18b09c460c.r2` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"contains_any": ["master.passwd"]}}` |
| `llm.llm-llm-credential-dump-passwd-e29b984306-71ac01.831b8b4306.r2` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"all_of": [{"contains_any": ["passwd"]}, {"contains_any": ["/tmp"]}, {"contains_any": ["cat"]}]}}` |
| `llm.llm-user-writable-outbound-connection-b85e043ed0.9811af3ed0.r1` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "host_network_connection", "lineage.user_writable": {"truthy": true}, "facts.direction": "outbound"}` |
| `llm.llm-user-writable-outbound-server-c5a7a22a21.174bd32a21.r1` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "lineage.user_writable": {"truthy": true}, "facts.command": {"contains_any": ["-server"]}}` |
| `llm.network-neighbor-discovery.60f1e49074` | active | passed C5: agrees with hand:TA0007@run1_app01_1330, hand:KILLCHAIN@run1_ws-fin01_1330 | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "any_of": [{"facts.image": "ip"}, {"facts.image": "arp"}], "facts.command": {"contains_any": ["neighbour", "neighbor", "arp"]}}` |
| `llm.network-neighbor-discovery.9c1dbbce38` | active | passed C5: agrees with hand:TA0007@run1_app01_1330, hand:KILLCHAIN@run1_ws-fin01_1330 | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.image": ["ip", "arp"], "facts.command": {"contains_any": ["neighbour", "-a"]}}` |
| `llm.network-neighbor-discovery.fa93f564ae` | active | passed C5: agrees with hand:TA0007@run1_app01_1330, hand:KILLCHAIN@run1_ws-fin01_1330 | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.image": ["ip"], "facts.command": {"contains_any": ["neighbour", "show"]}}` |
| `llm.read-passwd-to-tmp.952833f90c` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"all_of": [{"contains_any": ["/etc/passwd"]}, {"contains_any": ["/tmp/"]}]}}` |
| `llm.user-writable-discovery-commands.604cde8671` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "lineage.ancestor_user_writable": {"truthy": true}, "facts.command": {"contains_any": ["whoami", "env"]}}` |
| `llm.user-writable-history-clear.7670068671` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.image": ["dash", "sh"], "lineage.parent_user_writable": {"truthy": true}, "facts.command": {"all_of": [{"contains_any": ["bash_history"]}, {"contains_any": ["unset"]}]}}` |
| `llm.user-writable-outbound-connection.89fb558671.r2` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "host_network_connection", "facts.direction": "outbound", "lineage.user_writable": {"truthy": true}}` |
| `llm.whoami-from-user-writable-ancestor.5f35e53ed0` | active | analyst-approved: analyst verdicts 4 malicious / 0 benign (mean 0.83, lower 0.51; all 4 alert(s) reviewed) | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"contains_any": ["whoami"]}, "lineage.ancestor_user_writable": {"truthy": true}}` |
| `llm.clear-bash-history.f07f116a50` | retired | duplicate of llm.clear-bash-history.f07f113ed0 | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"contains_any": ["bash_history", "unset"]}}` |
| `llm.copy-auth-logs-to-tmp.1aee330795` | retired | analyst: analyst verdicts 0 malicious / 5 benign (mean 0.14, lower 0.00; all 5 alert(s) reviewed) | 1/8 · 4/12 · 0.0 | `{"claim_type": "process_create", "any_of": [{"facts.image": "sudo", "facts.command": {"all_of": [{"contains_any": ["cp"]}, {"contains_any": ["auth.log"]}, {"contains_any": ["/tmp"]}]}}, {"facts.image": "bash", "facts.com` |
| `llm.shadow-read-detection.c794b7815c` | retired | analyst: analyst verdicts 0 malicious / 5 benign (mean 0.14, lower 0.00; all 5 alert(s) reviewed) | 0/8 · 5/12 · 0.0 | `{"claim_type": "file_read", "facts.file_path": {"contains_any": ["shadow"]}, "facts.image": {"not_in": ["login", "sshd", "passwd", "su", "sudo", "systemd", "polkit"]}}` |
| `llm.user-writable-outbound-connection-b85e046a50.9811af6a50.r1` | retired | duplicate of llm.llm-user-writable-outbound-connection-b85e043ed0.9811af3ed0.r1 | 4/8 · 0/12 · 1.0 | `{"claim_type": "host_network_connection", "lineage.user_writable": {"truthy": true}, "facts.direction": "outbound"}` |
| `llm.whoami-from-user-writable-ancestor.5f35e56a50` | retired | duplicate of llm.whoami-from-user-writable-ancestor.5f35e53ed0 | 4/8 · 0/12 · 1.0 | `{"claim_type": "process_create", "facts.command": {"contains_any": ["whoami"]}, "lineage.ancestor_user_writable": {"truthy": true}}` |
| `llm.clear-bash-history.547eba2a21` | rejected | repaired: superseded by llm.llm-user-writable-outbound-server-c5a7a22a21.174bd32a21.r1,llm.llm-clear-bash-history-547eba2a21.f68ca72a21.r1,l |  ·  ·  | `{"claim_type": "process_create", "facts.image": ["dash"], "facts.command": {"contains_any": ["HISTFILE", "bash_history"]}}` |
| `llm.credential-dump-etc-passwd.69392085b1` | rejected | repaired: superseded by llm.credential-dump-etc-master-passwd.60d65985b1.r1 |  ·  ·  | `{"claim_type": "file_read", "facts.file_path": {"contains_any": ["/etc/master.passwd"]}, "facts.image": ["cat"], "behaviour.tactics": {"in": ["credential-access"]}}` |
| `llm.credential-dump-master-passwd.b0f086460c` | rejected | repaired: superseded by llm.llm-credential-dump-master-passwd-b0f086460c.dfe510460c.r1 |  ·  ·  | `{"claim_type": "process_create", "facts.command": {"contains_any": ["master.passwd"]}, "behaviour.tactics": {"in": ["credential-access"]}}` |
| `llm.credential-dump-passwd.414cfd5de7` | rejected | repaired: superseded by llm.llm-credential-dump-passwd-414cfd5de7.0d5af25de7.r1 |  ·  ·  | `{"claim_type": "process_create", "facts.command": {"all_of": [{"contains_any": ["etc/passwd"]}, {"contains_any": ["/tmp/"]}]}, "behaviour.tactics": {"in": ["credential-access"]}}` |
| `llm.credential-dump-passwd.e29b984306` | rejected | repaired: superseded by llm.llm-credential-dump-passwd-e29b984306.71ac014306.r1 |  ·  ·  | `{"claim_type": "process_create", "any_of": [{"facts.image": "cat"}, {"facts.image": "sh"}], "facts.command": {"all_of": [{"contains_any": ["passwd"]}, {"contains_any": ["/tmp"]}]}, "behaviour.tactics": {"in": ["credentia` |
| `llm.discovery-from-user-writable-parent.e333f02a21` | rejected | repaired: superseded by llm.llm-user-writable-outbound-server-c5a7a22a21.174bd32a21.r1,llm.llm-clear-bash-history-547eba2a21.f68ca72a21.r1,l |  ·  ·  | `{"claim_type": "process_create", "lineage.parent_user_writable": {"truthy": true}, "facts.command": {"contains_any": ["whoami"]}}` |
| `llm.install-iproute2-apt-get.adfcdace38.r1` | rejected | C4_rare_history: fires on 50% of the host's other captures (max 25%) | 4/8 · 8/12 · 0.1667 | `{"claim_type": "process_create", "facts.image": ["dash", "sh", "bash"], "facts.command": {"contains_any": ["apt-get", "install", "iproute2"]}}` |
| `llm.install-iproute2-apt.4452b6ce38` | rejected | repaired: superseded by llm.install-iproute2-apt-get.adfcdace38.r1 |  ·  ·  | `{"claim_type": "process_create", "facts.image": ["sh", "bash"], "facts.command": {"contains_any": ["apt-get", "install", "iproute2"]}}` |
| `llm.linux-etc-passwd-temp-dump.4fd26e7236` | rejected | C4_rare_history: fires on 75% of the host's other captures (max 25%) | 5/8 · 8/12 · 0.2469 | `{"claim_type": "process_create", "facts.command": {"contains_any": ["passwd", "/tmp/"]}}` |
| `llm.llm-credential-dump-master-passwd-b0f086460c.dfe510460c.r1` | rejected | repaired: superseded by llm.llm-llm-credential-dump-master-passwd-b0f086460c.18b09c460c.r2 |  ·  ·  | `{"claim_type": "process_create", "facts.command": {"contains_any": ["master.passwd"]}}` |
| `llm.llm-credential-dump-passwd-e29b984306.71ac014306.r1` | rejected | repaired: superseded by llm.llm-llm-credential-dump-passwd-e29b984306-71ac01.831b8b4306.r2 |  ·  ·  | `{"claim_type": "process_create", "any_of": [{"facts.image": "cat"}, {"facts.image": "sh"}], "facts.command": {"all_of": [{"contains_any": ["passwd"]}, {"contains_any": ["/tmp"]}]}}` |
| `llm.shadow-file-read.27bd464f25` | rejected | C4_rare_history: fires on 100% of the host's other captures (max 25%) | 7/8 · 12/12 · 0.0444 | `{"claim_type": "file_read", "facts.file_path": "/etc/shadow", "facts.image": {"not_in": ["login", "sshd", "su", "passwd", "pam_unix", "systemd", "init"]}}` |
| `llm.user-writable-outbound-connection-c031a58671.5f1dd48671.r1` | rejected | repaired: superseded by llm.user-writable-outbound-connection.89fb558671.r2 |  ·  ·  | `{"claim_type": "host_network_connection", "facts.direction": "outbound", "lineage.ancestor_user_writable": {"truthy": true}}` |
| `llm.user-writable-outbound-connection.b85e043ed0` | rejected | repaired: superseded by llm.llm-user-writable-outbound-connection-b85e043ed0.9811af3ed0.r1 |  ·  ·  | `{"claim_type": "host_network_connection", "lineage.ancestor_user_writable": {"truthy": true}, "facts.direction": "outbound"}` |
| `llm.user-writable-outbound-connection.b85e046a50` | rejected | repaired: superseded by llm.user-writable-outbound-connection-b85e046a50.9811af6a50.r1,llm.clear-bash-history-6f2c1d.b1bd756a50.r1 |  ·  ·  | `{"claim_type": "host_network_connection", "lineage.ancestor_user_writable": {"truthy": true}, "facts.direction": "outbound"}` |
| `llm.user-writable-outbound-connection.c031a58671` | rejected | repaired: superseded by llm.user-writable-outbound-connection-c031a58671.5f1dd48671.r1 |  ·  ·  | `{"claim_type": "host_network_connection", "direction": "outbound", "lineage.ancestor_user_writable": {"truthy": true}}` |
| `llm.user-writable-outbound-server.c5a7a22a21` | rejected | repaired: superseded by llm.llm-user-writable-outbound-server-c5a7a22a21.174bd32a21.r1,llm.llm-clear-bash-history-547eba2a21.f68ca72a21.r1,l |  ·  ·  | `{"claim_type": "process_create", "lineage.user_writable": {"truthy": true}, "facts.command": {"contains_any": ["-server"]}}` |
