#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./run_molecule.sh ROLE_NAME [test|converge|verify|lint] [DB_FILTER]
# Examples:
#   ./run_molecule.sh zabbix_proxy
#   ./run_molecule.sh zabbix_proxy test pgsql
#   KEEP=1 ./run_molecule.sh zabbix_proxy converge pgsql

ROLE="${1:-}"
ACTION="${2:-test}"
DB_FILTER="${3:-}"   # e.g. pgsql | mysql | mariadb

if [[ -z "$ROLE" ]]; then
  echo "Usage: ./run_molecule.sh ROLE_NAME [test|converge|verify|lint] [DB_FILTER]" >&2
  exit 1
fi

# Ensure we're at the repo root (must see molecule/)
if [[ ! -d molecule ]]; then
  echo "ERROR: Run from repo root (molecule/ not found)." >&2
  exit 1
fi

# Bootstrap venv
PY="${PYTHON_BIN:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "ERROR: $PY not found (set PYTHON_BIN=... if needed)." >&2
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# Ensure toolchain (idempotent)
python -m pip install -U pip >/dev/null
python - <<'PY'
import importlib.util, sys, subprocess
def have(mod): return importlib.util.find_spec(mod) is not None
def pip(*args): subprocess.check_call([sys.executable, "-m", "pip", *args])

# core
if not have("ansible"):            pip("install","ansible-core>=2.15")
if not have("molecule"):           pip("install","molecule")
# docker driver plugin
if not have("molecule_plugins"):   pip("install","molecule-plugins[docker]")
# verifier deps
if not have("pytest"):             pip("install","pytest")
if not have("testinfra"):          pip("install","testinfra")
PY

# Molecule must be on PATH from the venv
if ! command -v molecule >/dev/null 2>&1; then
  echo "ERROR: 'molecule' CLI not found in PATH (venv). Check installation." >&2
  exit 1
fi

# Find scenarios referencing the role
mapfile -t SCENARIOS < <(find molecule -maxdepth 1 -mindepth 1 -type d -printf "%f\n")
MATCHED=()
for scen in "${SCENARIOS[@]}"; do
  cfg="molecule/$scen/converge.yml"
  [[ -f "$cfg" ]] || continue
  if grep -Eiq "(role\s*:\s*${ROLE}\b|name\s*:\s*${ROLE}\b|community\.zabbix\.${ROLE}\b|role\s*:\s*community\.zabbix\.${ROLE}\b|include_role:\s*name:\s*${ROLE}\b)" "$cfg"; then
    MATCHED+=("$scen")
  fi
done

# Also support role-local scenarios under roles/<role>/molecule/*
if [[ -d "roles/$ROLE/molecule" ]]; then
  while IFS= read -r scen; do
    [[ -z "$scen" || "$scen" == "." ]] && continue
    MATCHED+=("$scen")
  done < <(find "roles/$ROLE/molecule" -maxdepth 1 -mindepth 1 -type d -printf "%f\n")
fi

if [[ ${#MATCHED[@]} -eq 0 ]]; then
  echo "ERROR: No scenarios found referencing role '$ROLE'." >&2
  exit 2
fi

echo "[INFO] Will run scenarios: ${MATCHED[*]}"
if [[ -n "$DB_FILTER" ]]; then
  echo "[INFO] DB filter active: _database_groups=['$DB_FILTER'] and --tags $DB_FILTER"
fi
if [[ "${KEEP:-}" == "1" && "$ACTION" == "converge" ]]; then
  echo "[INFO] KEEP=1 set: containers will be preserved after converge."
fi

for scen in "${MATCHED[@]}"; do
  echo "=== Running: molecule $ACTION -s $scen ==="

  # Limit pytest collection to this scenario's tests & move its cache locally
  export PYTEST_ADDOPTS="-o testpaths=$(pwd)/molecule/$scen/tests -o cache_dir=$(pwd)/.pytest_cache_$scen"

  # Build the command
  cmd=(molecule "$ACTION" -s "$scen")

  # Keep containers (only meaningful on converge)
  if [[ "$ACTION" == "converge" && "${KEEP:-}" == "1" ]]; then
    cmd+=("--destroy=never")
  fi

  # Append extra Ansible args after the '--' separator
  if [[ -n "$DB_FILTER" ]]; then
    cmd+=("--" "--tags" "$DB_FILTER" "-e" "_database_groups=['$DB_FILTER']")
    # Limit to DB-specific instances only for actions that operate on running hosts.
    case "$ACTION" in (converge|prepare|verify|idempotence|side_effect|cleanup|check)
      cmd+=("--limit" "*$DB_FILTER*")
      ;;
    esac
  fi

  echo "[INFO] CMD: ${cmd[*]}"
  ANSIBLE_REMOTE_TMP="${ANSIBLE_REMOTE_TMP:-/tmp/.ansible/tmp}" "${cmd[@]}"
done

echo "All done."
