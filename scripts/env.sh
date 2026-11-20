#!/bin/bash
# Shared environment for every project script.
# Source it at the top of a script:  source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
#
# Machine-specific values live in .env at the repo root (copy .env.example).
# Nothing in the scripts may contain a /home/<user> path.

# Repo root = parent of this scripts/ folder, wherever the repo is cloned
SDN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SDN_ROOT

# Home of the real user, also correct when the script runs under sudo
SDN_USER_HOME="$(getent passwd "${SUDO_USER:-$(id -un)}" | cut -d: -f6)"
SDN_USER_HOME="${SDN_USER_HOME:-$HOME}"
export SDN_USER_HOME

# Load .env without overriding variables already set in the shell
if [ -f "$SDN_ROOT/.env" ]; then
    while IFS='=' read -r key value; do
        case "$key" in ''|\#*) continue ;; esac
        key="$(echo "$key" | xargs)"
        value="$(echo "$value" | sed -e 's/^ *//' -e 's/ *$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
        value="${value/#\~/$SDN_USER_HOME}"
        [ -z "${!key}" ] && [ -n "$value" ] && export "$key=$value"
    done < "$SDN_ROOT/.env"
fi

# Defaults (match config/settings.py)
export SDN_RUNTIME_DIR="${SDN_RUNTIME_DIR:-/tmp}"
export SDN_LOG_DIR="${SDN_LOG_DIR:-$SDN_ROOT/logs}"
export SDN_CONTROLLER_PORT="${SDN_CONTROLLER_PORT:-6653}"
export SDN_VENV="${SDN_VENV:-$SDN_USER_HOME/venvs/ryu-py310}"

mkdir -p "$SDN_RUNTIME_DIR" "$SDN_LOG_DIR" 2>/dev/null || true
