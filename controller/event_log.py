"""
Stage timestamp log for experiments (interface: docs/interfaces.md).

Every stage of detection and mitigation is appended as one JSON object per
line to settings.EVENTS_FILE (default <repo>/logs/events.jsonl):

  {"ts": 1764000000.123, "stage": "decision", "run_id": "...", "policy": "...",
   "attack": "...", "src_ip": "10.0.1.1", ...}

Controller stages: alert, ml_positive, decision, flowmod_sent, barrier_ack,
block_verified, release, expiry, flow_removed.
The experiment harness adds attack_start / attack_end, and the analysis adds
victim_last_pkt from the victim's capture.

run_id, policy and attack come from settings.CURRENT_RUN_FILE, which the
harness rewrites before each run, so a long-running controller tags events
with the run that is in progress.
"""
import json
import os
import threading
import time


class EventLogger:
    def __init__(self, events_file, current_run_file, default_policy="hybrid"):
        self.events_file = str(events_file)
        self.current_run_file = str(current_run_file)
        self.default_policy = default_policy
        self._lock = threading.Lock()
        self._run_cache = {}
        self._run_mtime = None
        os.makedirs(os.path.dirname(self.events_file) or ".", exist_ok=True)
        # Controller (user) and harness (sudo) both append: keep it writable for both
        try:
            if not os.path.exists(self.events_file):
                open(self.events_file, "a").close()
            os.chmod(self.events_file, 0o666)
        except OSError:
            pass

    def current_run(self):
        """The run in progress (dict from CURRENT_RUN_FILE, {} if none)."""
        return self._current_run()

    def _current_run(self):
        try:
            mtime = os.path.getmtime(self.current_run_file)
        except OSError:
            self._run_cache, self._run_mtime = {}, None
            return {}
        if mtime != self._run_mtime:
            try:
                with open(self.current_run_file) as f:
                    self._run_cache = json.load(f)
            except (OSError, ValueError):
                self._run_cache = {}
            self._run_mtime = mtime
        return self._run_cache

    def log(self, stage, **fields):
        """Append one event. Never raises: logging must not break the controller."""
        try:
            run = self._current_run()
            event = {
                "ts": time.time(),
                "stage": stage,
                "run_id": run.get("run_id", "adhoc"),
                "policy": run.get("policy", self.default_policy),
                "attack": run.get("attack", "unknown"),
            }
            event.update({k: v for k, v in fields.items() if v is not None})
            line = json.dumps(event, default=str)
            with self._lock:
                with open(self.events_file, "a") as f:
                    f.write(line + "\n")
        except Exception:
            pass
