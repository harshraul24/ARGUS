#!/usr/bin/env bash
# package_batch.sh — turn a run_batch.sh capture dir into triaged ARGUS cases (on the MAC).
#
# For each per-service run dir it: labels the campaign, packages a case into
# cases_linux/apt_live_NNN, and runs triage — saving results next to the case.
#
# Usage (from the ARGUS repo root, with the venv active + PYTHONPATH set):
#   cd <repo root> && source .venv/bin/activate
#   export PYTHONPATH="source code"
#   tools/apt_capture/package_batch.sh captures/batch_20260910_XXXXXX
#
# Optional: WITH_NET=1 to include Zeek network logs (filters out the huge conn.log).
set -uo pipefail

BATCH="${1:?usage: package_batch.sh <captures/batch_dir>}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
WITH_NET="${WITH_NET:-0}"
START_N="${START_N:-2}"   # first case number -> apt_live_002 (001 already exists)

n="$START_N"
for RUN in "$BATCH"/*/; do
    [ -d "$RUN" ] || continue
    label="$(basename "$RUN")"
    log="$RUN/APT-Agent_experiment_log.txt"
    auth="$RUN/captured/auth.log"
    [ -f "$log" ] || { echo "[skip] $label: no experiment log"; continue; }
    [ -f "$auth" ] || { echo "[skip] $label: no auth.log"; continue; }
    start="$(cat "$RUN/CAMPAIGN_START" 2>/dev/null || echo 2026-01-01T00:00:00Z)"
    caseid="$(printf 'apt_live_%03d' "$n")"
    out="cases_linux/$caseid"

    echo "=== [$caseid] $label  (start $start) ==="
    python3 tools/apt_capture/label_campaign.py "$log" --start "$start" --out "$RUN/ground_truth.json" || continue

    netargs=()
    if [ "$WITH_NET" = "1" ] && [ -d "$RUN/zeek" ]; then
        # keep the small useful zeek logs; drop the multi-hundred-MB conn.log scan noise
        mkdir -p "$RUN/zeek_small"
        for f in "$RUN"/zeek/*.log; do
            [ -f "$f" ] || continue
            case "$(basename "$f")" in
                conn.log) [ "$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f")" -lt 5000000 ] && cp "$f" "$RUN/zeek_small/";;
                *) cp "$f" "$RUN/zeek_small/";;
            esac
        done
        netargs=(--net "$RUN/zeek_small")
    fi

    python3 tools/apt_capture/to_argus_case.py \
        --auth "$auth" $( [ -f "$RUN/captured/syslog" ] && echo --syslog "$RUN/captured/syslog" ) \
        ${netargs[@]+"${netargs[@]}"} \
        --ground-truth "$RUN/ground_truth.json" \
        --target-ip "${TARGET_IP:-10.0.2.20}" --attacker-ip "${ATTACKER_IP:-10.0.2.10}" \
        --category attack --title "APT-Agent $label (live Metasploitable2)" \
        --out "$out" || continue

    mkdir -p "$out/results"
    python3 -m argus.cli triage "$out" > "$out/results/triage_deterministic.json" 2>/dev/null
    # one-line summary
    python3 - "$out/results/triage_deterministic.json" <<'PY'
import sys, json
d = json.load(open(sys.argv[1]))
hs = "  ".join(f"{h.get('technique','?')} {h.get('score',0):.2f}" for h in d.get("hypotheses", []))
print(f"    -> {d.get('disposition')}  sev {d.get('severity')}  claims {d.get('claims_considered')}/{d.get('claims_total')}  [{hs}]")
PY
    n=$((n+1))
done

echo
echo "[+] packaged $((n-START_N)) case(s) into cases_linux/. Compare against each ground_truth.json."
