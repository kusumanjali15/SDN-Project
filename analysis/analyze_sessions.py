#!/usr/bin/env python3
"""
Turn a capture or experiment run into the paper's tables.

Inputs (all produced by scripts/run_sessions.py and the controller):
  <run_dir>/schedule.csv       ground truth: attacker, victim, attack window
  <run_dir>/*_victim.pcap      traffic as the victim saw it
  events.jsonl                 controller stage log (alert, decision, ...)

Usage:
  python3 analysis/analyze_sessions.py <run_dir> <events.jsonl> [--out <dir>]

Outputs in <out> (default <run_dir>/analysis):
  sessions.csv   one row per session with every measured value
  summary.md     detection, mitigation latency, false isolation, false alarms

No third-party packages needed: pcaps are read with a small built-in parser.

Definitions (also used in the paper):
  detection time     attack start -> controller decision for the attacker
  verified time      decision -> all switches confirmed the rule (barrier)
  containment time   attack start -> last attack packet seen at the victim
  residual packets   attack packets reaching the victim after confirmation
  false isolation    a decision (block) against a host that is not the
                     session's attacker
  false alarm        an alert, approved or not, naming a non-attacker source
"""
import argparse
import csv
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median


# ------------------------------------------------------------------ pcap
def read_pcap(path):
    """Yield (ts, src_ip, dst_ip, proto) for IPv4 packets in a classic pcap."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            raise ValueError(f"{path}: not a classic pcap file")
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        if linktype != 1:
            raise ValueError(f"{path}: link type {linktype}, expected Ethernet")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _ = struct.unpack(endian + "IIII", rec)
            data = f.read(incl)
            if len(data) < 34:
                continue
            ethertype = struct.unpack("!H", data[12:14])[0]
            off = 14
            if ethertype == 0x8100:  # VLAN tag
                ethertype = struct.unpack("!H", data[16:18])[0]
                off = 18
            if ethertype != 0x0800:
                continue
            ip = data[off:off + 20]
            proto = ip[9]
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
            yield sec + frac / (1e9 if nano else 1e6), src, dst, proto


# ------------------------------------------------------------------ helpers
def fnum(x, nd=2):
    return "" if x is None else f"{x:.{nd}f}"


def med(xs):
    xs = [x for x in xs if x is not None]
    return median(xs) if xs else None


def pct(xs, q):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def first(events, **match):
    for e in events:
        if all(e.get(k) == v for k, v in match.items()):
            return e
    return None


# ------------------------------------------------------------------ analysis
def analyze(run_dir, events_path):
    rows = list(csv.DictReader(open(run_dir / "schedule.csv")))
    run_ids = {r["run_id"] for r in rows}
    by_run = defaultdict(list)
    with open(events_path) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("run_id") in run_ids:
                by_run[e["run_id"]].append(e)
    for evs in by_run.values():
        evs.sort(key=lambda e: e["ts"])

    out = []
    for r in rows:
        evs = by_run.get(r["run_id"], [])
        attacker, victim = r["attacker_ip"], r["victim_ip"]
        a_start = float(r["attack_start"]) if r["attack_start"] else None
        a_end = float(r["attack_end"]) if r["attack_end"] else None
        s_start, s_end = float(r["session_start"]), float(r["session_end"])
        rec = {k: r[k] for k in ("run_id", "mode", "policy", "scenario", "variant",
                                 "attacker_ip", "victim_ip")}
        rec["attack_duration_s"] = (a_end - a_start) if a_start and a_end else None

        # controller decisions and alerts
        dec_att = first(evs, stage="decision", src_ip=attacker) if attacker else None
        alert_att = None
        if attacker:
            alert_att = next((e for e in evs if e["stage"] == "alert" and e.get("src_ip") == attacker
                              and e.get("approved")), None)
        ver_att = first(evs, stage="block_verified", src_ip=attacker) if attacker else None
        rec["detected"] = dec_att is not None
        rec["detection_rule"] = (dec_att or {}).get("reason", "")
        rec["t_alert_s"] = (alert_att["ts"] - a_start) if alert_att and a_start else None
        rec["t_decision_s"] = (dec_att["ts"] - a_start) if dec_att and a_start else None
        rec["enforced"] = bool(dec_att) and dec_att.get("enforced", True) is not False
        rec["decision_to_verified_ms"] = ver_att.get("decision_to_verified_ms") if ver_att else None

        false_dec = sorted({e["src_ip"] for e in evs if e["stage"] == "decision"
                            and e.get("src_ip") != attacker})
        false_enf = sorted({e["src_ip"] for e in evs if e["stage"] == "decision"
                            and e.get("src_ip") != attacker and e.get("enforced", True) is not False})
        rec["false_decisions"] = " ".join(false_dec)
        rec["false_isolations"] = " ".join(false_enf)
        rec["false_alarm_alerts"] = sum(1 for e in evs if e["stage"] == "alert"
                                        and e.get("src_ip") != attacker)

        # victim capture
        pcap = run_dir / r["victim_pcap"]
        att_ts, benign_before, benign_during = [], 0, 0
        if pcap.exists():
            for ts, src, dst, proto in read_pcap(pcap):
                if dst != victim:
                    continue
                if attacker and src == attacker:
                    if a_start and ts >= a_start - 0.5:
                        att_ts.append(ts)
                elif a_start:
                    if s_start <= ts < a_start:
                        benign_before += 1
                    elif a_start <= ts <= (a_end or s_end):
                        benign_during += 1
        rec["attack_pkts_at_victim"] = len(att_ts)
        if att_ts and a_start:
            rec["containment_s"] = max(att_ts) - a_start
            if dec_att:
                rec["pkts_before_decision"] = sum(1 for t in att_ts if t <= dec_att["ts"])
            if ver_att:
                rec["residual_pkts_after_verified"] = sum(1 for t in att_ts if t > ver_att["ts"])
                rec["verified_to_last_pkt_s"] = max(att_ts) - ver_att["ts"]
        if a_start:
            pre = max(a_start - s_start, 1e-6)
            dur = max((a_end or s_end) - a_start, 1e-6)
            rec["benign_pps_before"] = benign_before / pre
            rec["benign_pps_during"] = benign_during / dur
        out.append(rec)
    return out


def summarize(sessions, alerts_by_sig):
    L = []
    mode = sessions[0]["mode"] if sessions else "?"
    policy = sessions[0]["policy"] if sessions else "?"
    L.append(f"# Session analysis ({mode}, policy={policy}, {len(sessions)} sessions)\n")

    attacks = [s for s in sessions if s["scenario"] != "benign"]
    benign = [s for s in sessions if s["scenario"] == "benign"]

    L.append("## Detection (attack start -> controller decision)\n")
    L.append("| Attack | Variant | Detected | Median (s) | P90 (s) | Rule (first decision) |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    groups = defaultdict(list)
    for s in attacks:
        groups[(s["scenario"], s["variant"])].append(s)
    for (sc, va), ss in sorted(groups.items()):
        d = [s for s in ss if s["detected"]]
        t = [s["t_decision_s"] for s in d]
        rules = Counter(s["detection_rule"] for s in d).most_common(1)
        L.append(f"| {sc} | {va} | {len(d)}/{len(ss)} | {fnum(med(t))} | {fnum(pct(t, .9))} | "
                 f"{rules[0][0] if rules else '-'} |")
    for sc in sorted({s['scenario'] for s in attacks}):
        ss = [s for s in attacks if s["scenario"] == sc]
        d = [s for s in ss if s["detected"]]
        L.append(f"| **{sc} (all)** | | **{len(d)}/{len(ss)}** | "
                 f"**{fnum(med([s['t_decision_s'] for s in d]))}** | "
                 f"**{fnum(pct([s['t_decision_s'] for s in d], .9))}** | |")
    L.append("")

    if any(s["enforced"] for s in attacks):
        L.append("## Mitigation (enforced blocks)\n")
        L.append("| Attack | Blocked | Decision -> verified, median (ms) | Attack start -> last attack "
                 "pkt at victim, median (s) | Residual pkts after verified, median | "
                 "Benign pps at victim before / during |")
        L.append("| --- | --- | --- | --- | --- | --- |")
        for sc in sorted({s['scenario'] for s in attacks}):
            ss = [s for s in attacks if s["scenario"] == sc]
            b = [s for s in ss if s["enforced"]]
            L.append(f"| {sc} | {len(b)}/{len(ss)} | {fnum(med([s['decision_to_verified_ms'] for s in b]))} | "
                     f"{fnum(med([s.get('containment_s') for s in b]))} | "
                     f"{fnum(med([s.get('residual_pkts_after_verified') for s in b]), 0)} | "
                     f"{fnum(med([s.get('benign_pps_before') for s in ss]))} / "
                     f"{fnum(med([s.get('benign_pps_during') for s in ss]))} |")
        L.append("")

    L.append("## False isolation\n")
    fi_benign = [s for s in benign if s["false_isolations"] or (s["false_decisions"] and not s["enforced"])]
    fd_any = [s for s in sessions if s["false_decisions"]]
    fi_any = [s for s in sessions if s["false_isolations"]]
    L.append(f"- Benign-only sessions with any block decision: **{len(fi_benign)}/{len(benign)}**")
    L.append(f"- Sessions where a non-attacker host got a block decision: **{len(fd_any)}/{len(sessions)}**"
             + (f" (hosts: {', '.join(sorted({h for s in fd_any for h in s['false_decisions'].split()}))})"
                if fd_any else ""))
    L.append(f"- Of those, enforced (host actually isolated): **{len(fi_any)}**")
    L.append("")
    L.append("## Alerts on non-attacker sources (false alarms, logged)\n")
    if alerts_by_sig:
        L.append("| Signature | Count | Approved for blocking |")
        L.append("| --- | --- | --- |")
        for (sig, appr), n in sorted(alerts_by_sig.items(), key=lambda x: -x[1]):
            L.append(f"| {sig} | {n} | {'yes' if appr else 'no'} |")
    else:
        L.append("None.")
    L.append("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    ap.add_argument("events")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    run_dir = Path(args.run_dir)
    out_dir = Path(args.out) if args.out else run_dir / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    sessions = analyze(run_dir, Path(args.events))
    if not sessions:
        sys.exit("No sessions found")

    # false-alarm alerts by signature (non-attacker sources)
    sched = {r["run_id"]: r["attacker_ip"] for r in csv.DictReader(open(run_dir / "schedule.csv"))}
    alerts = Counter()
    with open(args.events) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("stage") == "alert" and e.get("run_id") in sched and e.get("src_ip") != sched[e["run_id"]]:
                alerts[(e.get("signature", "?"), bool(e.get("approved")))] += 1

    fields = list(dict.fromkeys(k for s in sessions for k in s))
    with open(out_dir / "sessions.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for s in sessions:
            w.writerow({k: (fnum(v, 4) if isinstance(v, float) else v) for k, v in s.items()})
    summary = summarize(sessions, alerts)
    (out_dir / "summary.md").write_text(summary)
    print(summary)
    print(f"\nWritten: {out_dir / 'sessions.csv'}, {out_dir / 'summary.md'}")


if __name__ == "__main__":
    main()
