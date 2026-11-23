# Reference environment (Kali testbed)

Everyone matches these versions. `scripts/check_env.sh` checks them.

## Python environments

| Environment | Python | Used for | Packages |
| --- | --- | --- | --- |
| Ryu venv (default `~/venvs/ryu-py310`) | 3.10.13 | Controller, ML training and inference, analysis | `requirements-full.lock` (testbed), `requirements-ml.lock` (B and C) |
| CICFlowMeter venv (`~/venvs/cicflow`) | 3.12 or newer | Flow feature extraction (live and from pcaps) | `requirements-cicflow.lock` |

CICFlowMeter needs Python >= 3.12 and Ryu needs 3.10, so they run in separate
environments. CICFlowMeter runs as its own process and writes flows to a file
or URL that the controller reads.

Key Python packages (Ryu venv):

| Package | Version | Note |
| --- | --- | --- |
| ryu | 4.34 | |
| eventlet | 0.40.4 | Newer than Ryu usually expects, but works here. Do not change. |
| scikit-learn | 1.7.2 | Must match: the trained `.pkl` models were saved with 1.7.2 |
| numpy | 2.2.6 | |
| pandas | 2.3.3 | |
| scipy | 1.15.3 | |
| joblib | 1.5.2 | |
| tensorflow | 2.20.0 | Autoencoder |
| torch | 2.10.0+cpu | Old LSTM only; being removed from the decision path |

## System software

| Component | Version |
| --- | --- |
| OS | Kali GNU/Linux 2025.3, kernel 6.16.8+kali-amd64 |
| Open vSwitch | 3.6.0 |
| Mininet | 2.3.0 |
| Suricata | 8.0.2 |
| Node-RED | v4.1.1 (Node.js v20.19.5) |

Do not upgrade any of these before the 25 Nov submission.
