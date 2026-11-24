#!/usr/bin/env python3
"""
Turn a capture run into a labelled flow dataset with CICFlowMeter features.

  python analysis/extract_flows.py <run_dir> <out.csv>

Needs the CICFlowMeter environment (Python >= 3.12, requirements-cicflow.lock):
  ~/venvs/cicflow/bin/python analysis/extract_flows.py data/captures/capture_X flows.csv

For every session's *_mirror.pcap (all traffic crossing switch s1) it runs
CICFlowMeter's FlowSession directly (the 0.5.0 command line passes its
arguments in the wrong order) and labels each flow from schedule.csv:

  label = <scenario>  if the flow's initiator is the session's attacker and
                      the flow starts inside [attack_start - 1 s, attack_end + 1 s]
  label = benign      otherwise (the attacker sends no benign traffic)

Columns added: session_id, scenario, variant, start_ts (epoch seconds),
label, is_attack. CICFlowMeter only emits TCP and UDP flows, so ICMP floods
are not represented here (the signature path covers them).
"""
import csv
import sys
from pathlib import Path

from scapy.all import PcapReader
from cicflowmeter import flow as cic_flow
from cicflowmeter.flow_session import FlowSession

# keep the exact flow start time (CICFlowMeter only writes a local-time string)
_orig_get_data = cic_flow.Flow.get_data


def _get_data(self, include_fields=None):
    data = _orig_get_data(self, include_fields)
    data["start_ts"] = float(self.start_timestamp)
    return data


cic_flow.Flow.get_data = _get_data


def flows_for(pcap, tmp_csv):
    session = FlowSession(output_mode="csv", output=str(tmp_csv), fields=None, verbose=False)
    for pkt in PcapReader(str(pcap)):
        if "IP" in pkt and ("TCP" in pkt or "UDP" in pkt):
            session.process(pkt)
    session.flush_flows()
    if not Path(tmp_csv).exists():
        return []
    with open(tmp_csv) as f:
        return list(csv.DictReader(f))


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    run_dir, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.parent.mkdir(parents=True, exist_ok=True)
    sched = list(csv.DictReader(open(run_dir / "schedule.csv")))
    all_rows, fields = [], None
    for n, s in enumerate(sched, 1):
        tmp = out.parent / f".tmp_{s['run_id']}.csv"
        tmp.unlink(missing_ok=True)
        rows = flows_for(run_dir / s["mirror_pcap"], tmp)
        tmp.unlink(missing_ok=True)
        a = s["attacker_ip"]
        a0 = float(s["attack_start"]) - 1 if s["attack_start"] else None
        a1 = float(s["attack_end"]) + 1 if s["attack_end"] else None
        counts = {}
        for r in rows:
            t = float(r["start_ts"])
            attack = bool(a) and r["src_ip"] == a and a0 is not None and a0 <= t <= (a1 or t)
            if a and r["src_ip"] == a and not attack:
                continue  # attacker flow outside the window: ambiguous, dropped
            r.update(session_id=s["run_id"], scenario=s["scenario"], variant=s["variant"],
                     label=s["scenario"] if attack else "benign", is_attack=int(attack))
            counts[r["label"]] = counts.get(r["label"], 0) + 1
            all_rows.append(r)
        print(f"[{n}/{len(sched)}] {s['run_id']}: {counts}", flush=True)
        if rows and fields is None:
            fields = list(all_rows[0].keys())
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(all_rows)
    print(f"Wrote {len(all_rows)} flows to {out}")


if __name__ == "__main__":
    main()
