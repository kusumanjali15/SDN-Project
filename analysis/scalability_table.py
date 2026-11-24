#!/usr/bin/env python3
"""
Combine experiment runs of different topology sizes into one table.

  python3 analysis/scalability_table.py <events.jsonl> <run_dir> [<run_dir> ...]

Each run_dir is analysed with analyze_sessions.py first (results go to
<run_dir>/analysis/), then rows are grouped by number of hosts.
"""
import csv
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from statistics import median

HERE = Path(__file__).resolve().parent


def med(xs):
    xs = [float(x) for x in xs if x not in ("", None)]
    return median(xs) if xs else None


def f(x, nd=2):
    return "-" if x is None else f"{x:.{nd}f}"


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    events, run_dirs = sys.argv[1], [Path(d) for d in sys.argv[2:]]
    by_size = defaultdict(list)
    for d in run_dirs:
        subprocess.run([sys.executable, str(HERE / "analyze_sessions.py"), str(d), events],
                       check=True, stdout=subprocess.DEVNULL)
        for r in csv.DictReader(open(d / "analysis" / "sessions.csv")):
            by_size[int(float(r.get("n_hosts") or 8))].append(r)

    lines = ["| Hosts | Sessions | Attacks blocked | Detection, median (s) | Decision -> verified, "
             "median (ms) | Residual attack pkts, median | Benign hosts blocked | "
             "Controller CPU avg / max (%) |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for n in sorted(by_size):
        rows = by_size[n]
        att = [r for r in rows if r["scenario"] != "benign"]
        blocked = [r for r in att if r["enforced"] == "True"]
        fi = sum(1 for r in rows if r.get("false_isolations"))
        lines.append(
            f"| {n} | {len(rows)} | {len(blocked)}/{len(att)} | "
            f"{f(med(r['t_decision_s'] for r in blocked))} | "
            f"{f(med(r['decision_to_verified_ms'] for r in blocked))} | "
            f"{f(med(r.get('residual_pkts_after_verified') for r in blocked), 0)} | {fi} | "
            f"{f(med(r.get('controller_cpu_avg') for r in rows), 1)} / "
            f"{f(max((float(r['controller_cpu_max']) for r in rows if r.get('controller_cpu_max')), default=None), 1)} |")
    out = "\n".join(lines)
    print(out)
    (run_dirs[0].parent / "scalability_table.md").write_text(out + "\n")


if __name__ == "__main__":
    main()
