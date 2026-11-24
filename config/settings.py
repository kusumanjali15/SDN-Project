"""
Central settings for the SDN-IDS-IoT project.

Every path the code uses comes from here, so nothing depends on one
machine's username or folder layout. Machine-specific values go in a
`.env` file at the repo root (copied from `.env.example`, never committed)
or in environment variables.

Usage:
    from config import settings
    settings.EVE_JSON
"""
import os
from pathlib import Path

# Repo root = the folder that contains config/
ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv(path: Path) -> None:
    """Read KEY=VALUE lines from .env without overriding real env vars."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


_load_dotenv(ROOT / ".env")


def _user_home() -> Path:
    """Home of the real user, also when running under sudo (matches env.sh)."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except (ImportError, KeyError):
            pass
    return Path.home()


def _path(var: str, default: Path) -> Path:
    value = os.environ.get(var, "").strip()
    if not value:
        return default
    if value.startswith("~"):
        value = str(_user_home()) + value[1:]
    return Path(value)


# Shared runtime files (Suricata, topology, controller and scripts all use
# these). Default /tmp keeps today's behaviour; override with SDN_RUNTIME_DIR.
RUNTIME_DIR = _path("SDN_RUNTIME_DIR", Path("/tmp"))

EVE_JSON = RUNTIME_DIR / "eve.json"
SURICATA_ALERTS = RUNTIME_DIR / "suricata-alerts.json"
SURICATA_PORT_FILE = RUNTIME_DIR / "suricata_port.txt"
BLOCKED_IPS_FILE = RUNTIME_DIR / "blocked_ips.txt"
ML_ALERTS_FILE = RUNTIME_DIR / "ml_alerts.json"
COMMAND_FILE = RUNTIME_DIR / "controller_commands.txt"
ALERT_POSITION_FILE = RUNTIME_DIR / "alert_position.txt"
ML_DATA_DIR = RUNTIME_DIR / "ml_data"

# Project folders (always relative to the repo, never absolute)
CONFIG_DIR = ROOT / "config"
MODEL_DIR = _path("SDN_MODEL_DIR", ROOT / "ml" / "models" / "trained")
DATASET_DIR = _path("SDN_DATASET_DIR", ROOT / "ml" / "data" / "datasets")
LOG_DIR = _path("SDN_LOG_DIR", ROOT / "logs")

# Experiment logs (interface: docs/interfaces.md)
EVENTS_FILE = LOG_DIR / "events.jsonl"
CURRENT_RUN_FILE = RUNTIME_DIR / "current_run.json"


def _int(var: str, default: int) -> int:
    try:
        return int(os.environ.get(var, "").strip() or default)
    except ValueError:
        return default


def _float(var: str, default: float) -> float:
    try:
        return float(os.environ.get(var, "").strip() or default)
    except ValueError:
        return default


# Enforcement policy (Section IV of the paper). All overridable in .env.
# POLICY_MODE: which evidence may trigger a block
#   signature = approved Suricata alerts only
#   ml        = persistent ML positives only
#   hybrid    = either (default)
POLICY_MODE = os.environ.get("SDN_POLICY_MODE", "hybrid").strip().lower() or "hybrid"
# BLOCK_SCOPE: scoped = drop (src, dst, protocol); blanket = drop all traffic of the host
BLOCK_SCOPE = os.environ.get("SDN_BLOCK_SCOPE", "scoped").strip().lower() or "scoped"
BLOCK_HARD_TIMEOUT = _int("SDN_BLOCK_HARD_TIMEOUT", 120)     # seconds; 0 = never expire
BLOCK_MAX_TIMEOUT = _int("SDN_BLOCK_MAX_TIMEOUT", 900)       # cap for repeat offenders
BLOCK_REPEAT_MULTIPLIER = _float("SDN_BLOCK_REPEAT_MULTIPLIER", 2.0)
PERSISTENCE_R = _int("SDN_PERSISTENCE_R", 3)                 # ML positives needed ...
PERSISTENCE_WINDOW = _float("SDN_PERSISTENCE_WINDOW", 10.0)  # ... within this many seconds
ML_CONFIDENCE = _float("SDN_ML_CONFIDENCE", 0.60)            # RF confidence for a positive
# Live ML on packet-ins (true/false). Off = signature path only; ML is then
# evaluated offline on the captured pcaps. Keeps the controller fast under floods.
ML_LIVE = os.environ.get("SDN_ML_LIVE", "true").strip().lower() not in ("0", "false", "no", "off")
# Per-packet [LEARN]/[FLOW] lines. Off by default: under a flood they slow the
# controller down enough to stop forwarding.
VERBOSE_FLOWS = os.environ.get("SDN_VERBOSE_FLOWS", "false").strip().lower() in ("1", "true", "yes", "on")
AUTO_BLOCK_SIDS_FILE = _path("SDN_AUTO_BLOCK_SIDS_FILE", CONFIG_DIR / "auto_block_sids.txt")

# Network settings that differ between machines
MIRROR_IFACE = os.environ.get("SDN_MIRROR_IFACE", "")
CONTROLLER_PORT = int(os.environ.get("SDN_CONTROLLER_PORT", "6653"))


def ensure_dirs() -> None:
    """Create runtime and log folders if missing (safe to call repeatedly)."""
    for d in (RUNTIME_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    # `python -m config.settings` prints the resolved values
    for name in sorted(k for k in globals() if k.isupper()):
        print(f"{name} = {globals()[name]}")
