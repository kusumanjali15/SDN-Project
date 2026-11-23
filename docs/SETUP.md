# Setup for team members

Pick the path you need. Nothing machine-specific goes into the code: your
paths and settings go in `.env`, which is never committed.

## Path 1: Python only (ML, analysis, paper)

Works on Linux, macOS, or Windows via WSL2 (Ubuntu).

```bash
git clone https://github.com/kusumanjali15/SDN-Project.git
cd SDN-Project
python3.10 -m venv .venv              # must be Python 3.10 (pyenv install 3.10 if missing)
source .venv/bin/activate
pip install -r requirements-ml.lock
cp .env.example .env                  # edit only if a default does not suit you
./scripts/check_env.sh --ml           # every line must be PASS or WARN
```

Need CICFlowMeter (feature extraction from pcaps)? It needs its own Python 3.12+ venv:

```bash
python3.12 -m venv ~/venvs/cicflow
~/venvs/cicflow/bin/pip install -r requirements-cicflow.lock
~/venvs/cicflow/bin/cicflowmeter -f capture.pcap -c flows.csv
```

## Path 2: Testbed (Mininet, Ryu, Suricata, Node-RED)

1. Import the shared Kali VM (`kali-sdn.ova`) into VirtualBox or VMware.
2. Inside the VM:
   ```bash
   cd ~/sdn-project && git pull
   cp .env.example .env                # set SDN_VENV if your Ryu venv is elsewhere
   ./scripts/check_env.sh --full
   ```
3. Log in to GitHub with your own account.

## Daily rules

1. After each sync-point merge: `git pull origin main`, then `./scripts/check_env.sh`.
2. If something fails on your machine, do not edit code to make it work. Fix
   your `.env` or environment, or tell the folder's owner.
3. Never commit `.env`, `runtime/`, `logs/`, captures or pcaps.
4. New packages go through the lock-file owner (Person A), with an exact version.
5. Work only in the folders you own, on your own branch; merge via pull request.

## Where settings come from

| Setting | Default | Change it in |
| --- | --- | --- |
| Ryu venv | `~/venvs/ryu-py310` | `.env` `SDN_VENV` |
| Runtime files (eve.json, blocked_ips.txt, ...) | `/tmp` | `.env` `SDN_RUNTIME_DIR` |
| Logs | `<repo>/logs` | `.env` `SDN_LOG_DIR` |
| Models | `<repo>/ml/models/trained` | `.env` `SDN_MODEL_DIR` |
| Controller port | 6653 | `.env` `SDN_CONTROLLER_PORT` |

Python code reads these through `config/settings.py`; shell scripts through `scripts/env.sh`.
