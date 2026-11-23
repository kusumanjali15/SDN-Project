#!/bin/bash
# Check that this machine matches the reference environment (docs/ENVIRONMENT.md).
#
#   ./scripts/check_env.sh --ml     Python-only setup (Persons B and C)
#   ./scripts/check_env.sh --full   Testbed: also Ryu venv, OVS, Mininet, Suricata, Node-RED
#
# Run it after every `git pull`. Exit code 1 if anything FAILs.
# If something fails, do NOT edit code to make it work on your machine:
# fix your environment or .env, or tell the folder's owner.

source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "$SDN_ROOT" || exit 1

MODE="${1:---ml}"
case "$MODE" in --ml|--full) ;; *) echo "Usage: $0 [--ml|--full]"; exit 2 ;; esac

PASS=0; WARN=0; FAIL=0
pass() { echo "  PASS  $1"; PASS=$((PASS+1)); }
warn() { echo "  WARN  $1"; WARN=$((WARN+1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

# Reference versions (keep in sync with docs/ENVIRONMENT.md)
REF_PYTHON="3.10"
REF_RYU="4.34"
REF_OVS="3.6.0"
REF_SURICATA="8.0.2"
REF_MININET="2.3.0"
REF_NODERED="v4.1.1"

# In --full mode use the Ryu venv's Python; in --ml mode the active Python
if [ "$MODE" = "--full" ] && [ -x "$SDN_VENV/bin/python" ]; then
    PY="$SDN_VENV/bin/python"
else
    PY="$(command -v python3 || command -v python)"
fi

echo "== Repository"
echo "  root: $SDN_ROOT"
echo "  branch: $(git branch --show-current 2>/dev/null) @ $(git log -1 --format=%h 2>/dev/null)"
if [ -f .env ]; then pass ".env present"; else warn ".env missing (cp .env.example .env) - defaults will be used"; fi
# Only files tracked by git (ignores local venvs, caches and other untracked folders)
HARDCODED=$(git ls-files -z -- '*.py' '*.sh' '*.template' '*.yaml' \
            | grep -zv -e "^scripts/env.sh$" -e "^scripts/check_env.sh$" -e "^\.github/" \
            | xargs -0 -r grep -nE "/home/[a-z]" 2>/dev/null)
if [ -z "$HARDCODED" ]; then pass "no hard-coded /home/<user> paths in code"
else fail "hard-coded /home paths found:"; echo "$HARDCODED" | sed 's/^/        /'; fi

echo "== Python ($PY)"
PYVER=$("$PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null)
if [ "$PYVER" = "$REF_PYTHON" ]; then pass "Python $PYVER"
else fail "Python $PYVER, expected $REF_PYTHON (activate the right venv)"; fi

echo "== Packages vs requirements-ml.lock"
PKG_OUT=$("$PY" - <<'EOF'
import re, sys
from importlib.metadata import version, PackageNotFoundError
optional = {"tensorflow", "matplotlib", "pytest"}  # not everyone needs these
bad = 0
for line in open("requirements-ml.lock"):
    line = line.split("#")[0].strip()
    m = re.match(r"^([A-Za-z0-9_.\-]+)==(\S+)$", line)
    if not m:
        continue
    name, want = m.groups()
    try:
        have = version(name)
    except PackageNotFoundError:
        tag = "WARN" if name.lower() in optional else "FAIL"
        print(f"  {tag}  {name} not installed (want {want})")
        bad += tag == "FAIL"
        continue
    if have.split("+")[0] == want.split("+")[0]:
        print(f"  PASS  {name}=={have}")
    else:
        tag = "WARN" if name.lower() in optional else "FAIL"
        print(f"  {tag}  {name}=={have}, expected {want}")
        bad += tag == "FAIL"
sys.exit(1 if bad else 0)
EOF
)
echo "$PKG_OUT"
PASS=$((PASS + $(echo "$PKG_OUT" | grep -c '^  PASS')))
WARN=$((WARN + $(echo "$PKG_OUT" | grep -c '^  WARN')))
FAIL=$((FAIL + $(echo "$PKG_OUT" | grep -c '^  FAIL')))

echo "== Project config and models"
if "$PY" -c "from config import settings" 2>/dev/null; then
    pass "config/settings.py loads (runtime dir: $("$PY" -c 'from config import settings; print(settings.RUNTIME_DIR)'))"
else
    fail "config/settings.py does not import"
fi
MODEL_OUT=$("$PY" - 2>&1 <<'EOF'
import logging
logging.disable(logging.CRITICAL)
from config import settings
from ml.inference.predictor import MLPredictor
p = MLPredictor(model_dir=str(settings.MODEL_DIR))
print("OK" if p.load_models() else "FAILED")
EOF
)
if echo "$MODEL_OUT" | tail -1 | grep -q "^OK$"; then pass "trained models load from $(basename "$("$PY" -c 'from config import settings; print(settings.MODEL_DIR)')")"
else fail "trained models did not load:"; echo "$MODEL_OUT" | tail -5 | sed 's/^/        /'; fi

if [ "$MODE" = "--full" ]; then
    echo "== Testbed"
    if [ -x "$SDN_VENV/bin/ryu-manager" ]; then pass "ryu-manager in $SDN_VENV"
    else fail "ryu-manager not found in SDN_VENV=$SDN_VENV (set SDN_VENV in .env)"; fi
    RYU=$("$PY" -c 'from importlib.metadata import version; print(version("ryu"))' 2>/dev/null)
    [ "$RYU" = "$REF_RYU" ] && pass "ryu $RYU" || fail "ryu ${RYU:-missing}, expected $REF_RYU"

    OVS=$(ovs-vsctl --version 2>/dev/null | head -1 | awk '{print $NF}')
    [ "$OVS" = "$REF_OVS" ] && pass "Open vSwitch $OVS" || warn "Open vSwitch ${OVS:-missing}, reference $REF_OVS"
    SUR=$(suricata -V 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    [ "$SUR" = "$REF_SURICATA" ] && pass "Suricata $SUR" || warn "Suricata ${SUR:-missing}, reference $REF_SURICATA"
    MN=$(mn --version 2>&1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    [ "$MN" = "$REF_MININET" ] && pass "Mininet $MN" || warn "Mininet ${MN:-missing}, reference $REF_MININET"
    NR=$(node-red --version 2>/dev/null | grep -oE "v[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    [ "$NR" = "$REF_NODERED" ] && pass "Node-RED $NR" || warn "Node-RED ${NR:-missing}, reference $REF_NODERED"

    [ -f config/suricata.yaml.template ] && pass "Suricata config template present" || fail "config/suricata.yaml.template missing"
    [ -f config/custom.rules ] && pass "Suricata custom rules present" || fail "config/custom.rules missing"
    if [ -w "$SDN_RUNTIME_DIR" ]; then pass "runtime dir writable: $SDN_RUNTIME_DIR"
    else fail "runtime dir not writable: $SDN_RUNTIME_DIR"; fi
    if command -v cicflowmeter >/dev/null 2>&1 || [ -x "$SDN_USER_HOME/venvs/cicflow/bin/cicflowmeter" ]; then
        pass "cicflowmeter available"
    else
        warn "cicflowmeter not installed yet (see requirements-cicflow.lock; needed for A3)"
    fi
fi

echo
echo "Result: $PASS passed, $WARN warnings, $FAIL failed"
[ "$FAIL" -eq 0 ] || { echo "Fix the FAIL lines before starting work."; exit 1; }
