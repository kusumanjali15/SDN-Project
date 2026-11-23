#!/usr/bin/env python3
"""
Run labelled traffic sessions on the running Mininet testbed.

Two modes:

  capture     Build the test dataset. Benign traffic plus scheduled attacks,
              recorded as pcaps, with the attack schedule as ground truth.
              The controller logs its decisions but does NOT block
              (enforce=false), so every attack runs for its full duration.

  experiment  Measure mitigation. Same traffic, but the controller enforces
              the chosen policy. A capture on the victim shows when attack
              traffic actually stops. The controller is RESET between runs.

Run it while controller, topology and Suricata are up (see the team guide):

  sudo python3 scripts/run_sessions.py capture --sessions 10
  sudo python3 scripts/run_sessions.py experiment --policy signature --sessions 10

Ground-truth labels: a flow is malicious if its source is the session's
attacker IP and it starts inside [attack_start, attack_end]; everything else
is benign. The attacker host sends no benign traffic during its session, so
this rule is exact.

Outputs (default <repo>/data/captures/<mode>_<timestamp>/):
  <run_id>_mirror.pcap   all traffic mirrored to Suricata (switch s1)
  <run_id>_victim.pcap   traffic at the victim's interface
  schedule.csv           one row per session (ground truth)
  manifest.json          settings used, tool versions, seed
Stage events (attack_start, attack_end) go to logs/events.jsonl, next to
the controller's own events.
"""
import argparse
import csv
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import settings                      # noqa: E402
from controller.event_log import EventLogger     # noqa: E402

VLANS = {
    1: {"h1": "10.0.1.1", "h3": "10.0.1.3", "h5": "10.0.1.5", "h7": "10.0.1.7"},
    2: {"h2": "10.0.2.2", "h4": "10.0.2.4", "h6": "10.0.2.6", "h8": "10.0.2.8"},
}
ALL_HOSTS = {h: ip for v in VLANS.values() for h, ip in v.items()}
HTTP_PORT = 8080

# Attack variants: (label, command template, description). {victim} and {port}
# are filled in per session; rates vary so the detector sees easy and hard cases.
ATTACKS = {
    "icmp_flood": [
        ("icmp_2000pps", "hping3 --icmp -i u500 -q {victim}"),
        ("icmp_500pps", "hping3 --icmp -i u2000 -q {victim}"),
        ("icmp_100pps", "hping3 --icmp -i u10000 -q {victim}"),
        ("icmp_20pps", "hping3 --icmp -i u50000 -q {victim}"),
    ],
    "syn_flood": [
        ("syn_2000pps", "hping3 -S -p {port} -i u500 -q {victim}"),
        ("syn_500pps", "hping3 -S -p {port} -i u2000 -q {victim}"),
        ("syn_100pps", "hping3 -S -p {port} -i u10000 -q {victim}"),
        ("syn_20pps", "hping3 -S -p {port} -i u50000 -q {victim}"),
    ],
    "port_scan": [
        ("scan_T4_1024", "nmap -sS -Pn -T4 -p 1-1024 {victim}"),
        ("scan_T3_1024", "nmap -sS -Pn -T3 -p 1-1024 {victim}"),
        ("scan_T4_top100", "nmap -sS -Pn -T4 --top-ports 100 {victim}"),
        ("scan_T2_top100", "nmap -sS -Pn -T2 --top-ports 100 {victim}"),
    ],
    "syn_lowrate": [
        ("syn_10pps", "hping3 -S -p {port} -i u100000 -q {victim}"),
        ("syn_5pps", "hping3 -S -p {port} -i u200000 -q {victim}"),
    ],
}
SCENARIOS = ["benign"] + list(ATTACKS)
REQUIRED_TOOLS = ["mnexec", "tcpdump", "hping3", "nmap", "curl", "ping", "python3"]


# ---------------------------------------------------------------- helpers
def host_pid(name):
    """PID of a Mininet host's shell (`bash ... mininet:<name>`)."""
    out = subprocess.run(["pgrep", "-f", f"mininet:{name}$"], capture_output=True, text=True)
    pids = out.stdout.split()
    if not pids:
        raise RuntimeError(f"Mininet host '{name}' not found - is the topology running?")
    return pids[0]


class HostProcs:
    """Starts commands inside Mininet hosts and stops them all at the end."""

    def __init__(self):
        self.procs = []

    def start(self, host, cmd, stdout=subprocess.DEVNULL):
        p = subprocess.Popen(["mnexec", "-a", host_pid(host), "bash", "-c", cmd],
                             stdout=stdout, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        self.procs.append(p)
        return p

    def stop(self, p, sig=signal.SIGINT, wait=3):
        if p.poll() is None:
            try:
                os.killpg(p.pid, sig)
                p.wait(timeout=wait)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def stop_all(self):
        for p in reversed(self.procs):
            self.stop(p)
        self.procs.clear()


def tool_version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        line = (out.stdout or out.stderr).strip().splitlines()
        return line[0] if line else "?"
    except Exception:
        return "not found"


class NetworkDown(RuntimeError):
    pass


def network_ok(hosts, timeout=30):
    """Ping between all hosts of a VLAN; retry for up to `timeout` s.

    Catches a stalled controller before a session records useless pcaps.
    """
    pairs = list(zip(hosts, hosts[1:] + hosts[:1]))
    deadline = time.time() + timeout
    while True:
        bad = []
        for a, b in pairs:
            r = subprocess.run(["mnexec", "-a", host_pid(a), "ping", "-c", "1", "-W", "1",
                                ALL_HOSTS[b]], capture_output=True)
            if r.returncode != 0:
                bad.append(f"{a}->{b}")
        if not bad:
            return True
        if time.time() >= deadline:
            raise NetworkDown(f"no connectivity for {timeout}s: {', '.join(bad)}")
        time.sleep(2)


def write_current_run(run):
    tmp = Path(str(settings.CURRENT_RUN_FILE) + ".tmp")
    tmp.write_text(json.dumps(run))
    os.chmod(tmp, 0o644)
    tmp.replace(settings.CURRENT_RUN_FILE)


def send_command(cmd):
    with open(settings.COMMAND_FILE, "a") as f:
        f.write(cmd + "\n")
    try:
        os.chmod(settings.COMMAND_FILE, 0o666)
    except OSError:
        pass


def chown_to_user(path):
    """Files created under sudo belong to root; hand them back to the real user."""
    user = os.environ.get("SUDO_USER")
    if not user:
        return
    try:
        shutil.chown(path, user=user, group=user)
    except (LookupError, OSError):
        pass


# ---------------------------------------------------------------- session
def benign_loop_cmd(peers, rng):
    """IoT-like background traffic: one small request every 2-6 s.

    Mostly HTTP polling (telemetry/status), sometimes a single ping. About one
    ping per 10-20 s per device, well below the flood rules' thresholds (15
    pings in 10 s), so benign devices are not mistaken for attackers.
    """
    targets = " ".join(peers)
    return (
        f"peers=({targets}); n=${{#peers[@]}}; "
        f"for i in $(seq 1 100000); do "
        f"t=${{peers[RANDOM % n]}}; "
        f"if (( RANDOM % 3 == 0 )); then ping -c 1 -W 1 $t >/dev/null 2>&1; "
        f"else curl -s -m 2 -o /dev/null http://$t:{HTTP_PORT}/status ; fi; "
        f"sleep $((RANDOM % 5 + 2)).$((RANDOM % 10)); "
        f"done"
    )


def run_session(args, mode, scenario, idx, rng, out_dir, events, writer):
    run_id = f"{datetime.now():%Y%m%d_%H%M%S}_{scenario}_{args.policy}_run{idx:02d}"
    vlan = rng.choice(list(VLANS))
    hosts = list(VLANS[vlan])
    attacker, victim = rng.sample(hosts, 2) if scenario != "benign" else (None, rng.choice(hosts))
    variant, cmd_tpl = ("benign", None)
    if scenario != "benign":
        variant, cmd_tpl = rng.choice(ATTACKS[scenario])
    port = rng.choice([80, 22, 8080, 1883])
    attack_cmd = cmd_tpl.format(victim=ALL_HOSTS[victim], port=port) if cmd_tpl else ""
    duration = args.duration
    a_start_off = rng.uniform(*args.attack_start) if cmd_tpl else None
    a_len = rng.uniform(*args.attack_length) if cmd_tpl else None

    print(f"\n=== {run_id}: {scenario} ({variant}) "
          f"{'attacker ' + attacker + ' -> ' if attacker else ''}victim {victim} ===")

    if mode == "experiment":
        send_command("RESET:all")
        time.sleep(1.5)
    write_current_run({"run_id": run_id, "policy": args.policy, "attack": scenario,
                       "variant": variant, "enforce": mode == "experiment",
                       "attacker_ip": ALL_HOSTS.get(attacker), "victim_ip": ALL_HOSTS[victim]})

    for v_hosts in VLANS.values():
        network_ok(list(v_hosts))

    procs = HostProcs()
    mirror_pcap = out_dir / f"{run_id}_mirror.pcap"
    victim_pcap = out_dir / f"{run_id}_victim.pcap"
    row = {"run_id": run_id, "mode": mode, "policy": args.policy, "scenario": scenario,
           "variant": variant, "vlan": vlan, "attacker_host": attacker or "",
           "attacker_ip": ALL_HOSTS.get(attacker, ""), "victim_host": victim,
           "victim_ip": ALL_HOSTS[victim], "attack_cmd": attack_cmd,
           "session_start": "", "attack_start": "", "attack_end": "", "session_end": "",
           "mirror_pcap": mirror_pcap.name, "victim_pcap": victim_pcap.name}
    try:
        # captures
        procs.start("suricata", f"exec tcpdump -i suricata-eth0 -U -s 0 -w {mirror_pcap}")
        procs.start(victim, f"exec tcpdump -i {victim}-eth0 -U -s 0 -w {victim_pcap}")
        # HTTP servers on every host (benign targets)
        for h in ALL_HOSTS:
            procs.start(h, f"cd /tmp && exec python3 -m http.server {HTTP_PORT} --bind {ALL_HOSTS[h]}")
        time.sleep(1.5)

        session_start = time.time()
        row["session_start"] = f"{session_start:.6f}"
        events.log("session_start", scenario=scenario, variant=variant,
                   attacker_ip=row["attacker_ip"] or None, victim_ip=row["victim_ip"])

        # benign traffic from every host except the attacker, to peers in its own VLAN
        for v_hosts in VLANS.values():
            for h in v_hosts:
                if h == attacker:
                    continue
                peers = [ip for p, ip in v_hosts.items() if p != h]
                procs.start(h, benign_loop_cmd(peers, rng))

        attack_proc = None
        while True:
            now = time.time()
            elapsed = now - session_start
            if cmd_tpl and attack_proc is None and elapsed >= a_start_off:
                attack_proc = procs.start(attacker, f"exec timeout {a_len:.1f} {attack_cmd}")
                row["attack_start"] = f"{time.time():.6f}"
                events.log("attack_start", src_ip=row["attacker_ip"], dst_ip=row["victim_ip"],
                           variant=variant, command=attack_cmd)
                print(f"  attack started at +{elapsed:.1f}s for up to {a_len:.1f}s: {attack_cmd}")
            if attack_proc is not None and not row["attack_end"] and attack_proc.poll() is not None:
                row["attack_end"] = f"{time.time():.6f}"
                events.log("attack_end", src_ip=row["attacker_ip"], dst_ip=row["victim_ip"],
                           variant=variant)
                print(f"  attack ended at +{time.time() - session_start:.1f}s")
            if elapsed >= duration and (attack_proc is None or row["attack_end"]):
                break
            time.sleep(0.2)
    finally:
        procs.stop_all()
        row["session_end"] = f"{time.time():.6f}"
        events.log("session_end", scenario=scenario)
        for f in (mirror_pcap, victim_pcap):
            if f.exists():
                chown_to_user(f)
        writer.writerow(row)
        size = mirror_pcap.stat().st_size if mirror_pcap.exists() else 0
        if size < 20000:
            print(f"  WARNING: mirror capture is only {size} bytes - traffic may not be "
                  f"reaching Suricata (is the controller keeping up?)")

    if mode == "experiment":
        send_command("RESET:all")
    time.sleep(args.gap)
    return row


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["capture", "experiment"])
    ap.add_argument("--scenarios", default="benign,icmp_flood,syn_flood,port_scan",
                    help=f"comma list from: {', '.join(SCENARIOS)}")
    ap.add_argument("--sessions", type=int, default=10, help="sessions per scenario")
    ap.add_argument("--duration", type=float, default=60, help="seconds per session")
    ap.add_argument("--attack-start", type=float, nargs=2, default=(10, 20),
                    metavar=("MIN", "MAX"), help="attack starts this many seconds in")
    ap.add_argument("--attack-length", type=float, nargs=2, default=(15, 30),
                    metavar=("MIN", "MAX"), help="attack lasts this long (seconds)")
    ap.add_argument("--policy", default="capture",
                    help="experiment: signature | ml | hybrid (capture mode records 'capture')")
    ap.add_argument("--gap", type=float, default=5, help="pause between sessions (seconds)")
    ap.add_argument("--seed", type=int, default=None, help="random seed (default: time-based)")
    ap.add_argument("--out", default=None, help="output folder")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo: sudo python3 scripts/run_sessions.py ...")
    if args.mode == "experiment" and args.policy not in ("signature", "ml", "hybrid"):
        sys.exit("experiment mode needs --policy signature|ml|hybrid")
    if args.mode == "capture":
        args.policy = "capture"
    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    bad = [s for s in scenarios if s not in SCENARIOS]
    if bad:
        sys.exit(f"Unknown scenario(s): {bad}. Choose from {SCENARIOS}")
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    if missing:
        sys.exit(f"Missing tools: {missing}. Install with: sudo apt install -y "
                 + " ".join({'mnexec': 'mininet', 'ping': 'iputils-ping'}.get(t, t) for t in missing))
    for h in ["suricata"] + list(ALL_HOSTS):
        host_pid(h)  # fails early if the topology is not running

    seed = args.seed if args.seed is not None else int(time.time())
    rng = random.Random(seed)
    out_dir = Path(args.out) if args.out else \
        settings.ROOT / "data" / "captures" / f"{args.mode}_{datetime.now():%Y%m%d_%H%M%S}"
    out_dir.mkdir(parents=True, exist_ok=True)
    settings.ensure_dirs()
    events = EventLogger(settings.EVENTS_FILE, settings.CURRENT_RUN_FILE, default_policy=args.policy)

    plan = [(s, i) for s in scenarios for i in range(1, args.sessions + 1)]
    rng.shuffle(plan)  # interleave scenarios so drift over time doesn't bias one class
    est = len(plan) * (args.duration + args.gap + 4) / 60
    manifest = {
        "mode": args.mode, "policy": args.policy, "scenarios": scenarios,
        "sessions_per_scenario": args.sessions, "duration_s": args.duration,
        "attack_start_s": args.attack_start, "attack_length_s": args.attack_length,
        "seed": seed, "started": datetime.now().isoformat(), "attacks": ATTACKS,
        "tools": {t: tool_version(c) for t, c in {
            "hping3": ["hping3", "--version"], "nmap": ["nmap", "--version"],
            "tcpdump": ["tcpdump", "--version"]}.items()},
        "controller_settings": {k: str(getattr(settings, k)) for k in (
            "POLICY_MODE", "BLOCK_SCOPE", "BLOCK_HARD_TIMEOUT", "PERSISTENCE_R",
            "PERSISTENCE_WINDOW", "ML_CONFIDENCE")},
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"{len(plan)} sessions, about {est:.0f} minutes. Output: {out_dir}  (seed {seed})")

    sched_path = out_dir / "schedule.csv"
    fields = ["run_id", "mode", "policy", "scenario", "variant", "vlan", "attacker_host",
              "attacker_ip", "victim_host", "victim_ip", "attack_cmd", "session_start",
              "attack_start", "attack_end", "session_end", "mirror_pcap", "victim_pcap"]
    interrupted = False
    with open(sched_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        try:
            for n, (scenario, idx) in enumerate(plan, 1):
                print(f"[{n}/{len(plan)}]", end="")
                run_session(args, args.mode, scenario, idx, rng, out_dir, events, writer)
                f.flush()
        except KeyboardInterrupt:
            interrupted = True
            print("\nInterrupted - sessions finished so far are saved.")
        except NetworkDown as e:
            interrupted = True
            print(f"\nSTOPPED: {e}.\nThe controller has probably stalled. Restart controller, "
                  "topology and Suricata, then run again. Sessions finished so far are saved.")
        finally:
            write_current_run({"run_id": "adhoc", "policy": settings.POLICY_MODE,
                               "attack": "unknown", "enforce": True})
            subprocess.run(["pkill", "-f", f"http.server {HTTP_PORT}"], capture_output=True)
    for p in (sched_path, out_dir / "manifest.json", out_dir):
        chown_to_user(p)
    print(f"\n{'Partial' if interrupted else 'Done'}: {sched_path}")
    print("Copy for the team:  cp -r", out_dir, "/media/sf_sdn-share/captures/")


if __name__ == "__main__":
    main()
