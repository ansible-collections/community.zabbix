#!/usr/bin/env bash
set -euo pipefail

# Run a playbook directly against Molecule's *existing* containers,
# reusing Molecule's ephemeral inventory and the docker connection.
#
# Usage:
#   ./ansible-rerun.sh [SCENARIO] [PLAYBOOK] [-- EXTRA_ANSIBLE_ARGS...]
#
# Defaults:
#   SCENARIO = zabbix_server
#   PLAYBOOK = molecule/$SCENARIO/converge.yml
#
# Examples:
#   ./ansible-rerun.sh zabbix_server
#   ./ansible-rerun.sh zabbix_server 
#   ./ansible-rerun.sh zabbix_server molecule/zabbix_server/converge.yml -vvv
#
# Notes:
# - Requires that you've already done at least one `molecule converge` so the
#   ephemeral inventory exists and the containers are running.
# - If a Python venv (.venv) exists, it will be used automatically.

SCENARIO="${1:-zabbix_server}"; shift || true
PLAYBOOK="${1:-}"; if [[ -z "${PLAYBOOK:-}" || "${PLAYBOOK:-}" == "--" ]]; then
  PLAYBOOK="molecule/${SCENARIO}/converge.yml"
else
  shift || true
fi

# Anything left gets passed straight to ansible-playbook
EXTRA_ARGS=("$@")

# Activate venv if present
if [[ -d ".venv" ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

# Make sure ansible-playbook is available
if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "ERROR: ansible-playbook not found. Activate your venv or install Ansible." >&2
  exit 1
fi

# Try to find Molecule's latest ephemeral inventory for this scenario
find_inv_dir() {
  local patt1 patt2 cand
  patt1="$HOME/.ansible/tmp/molecule.*.${SCENARIO}"
  patt2="/root/.ansible/tmp/molecule.*.${SCENARIO}"   # fallback (common in sudo runs)
  cand="$(ls -td $patt1 2>/dev/null | head -1 || true)"
  [[ -z "$cand" ]] && cand="$(ls -td $patt2 2>/dev/null | head -1 || true)"
  echo "$cand"
}

INV_ROOT="$(find_inv_dir)"
INV_DIR="${INV_ROOT:+$INV_ROOT/inventory}"

if [[ -z "${INV_ROOT:-}" || ! -d "$INV_DIR" ]]; then
  echo "ERROR: Could not locate Molecule inventory for scenario '$SCENARIO'." >&2
  echo "       Run 'molecule converge -s $SCENARIO' once, then retry." >&2
  exit 2
fi

# Helpful defaults
export ANSIBLE_REMOTE_TMP="${ANSIBLE_REMOTE_TMP:-/tmp/.ansible/tmp}"
# If you keep roles locally, make resolution snappy
if [[ -d "./roles" ]]; then
  export ANSIBLE_ROLES_PATH="${ANSIBLE_ROLES_PATH:-$(pwd)/roles}"
fi

# Build the ansible-playbook command
cmd=(ansible-playbook -i "$INV_DIR" "$PLAYBOOK")



# Append any extra args the user provided
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  cmd+=("${EXTRA_ARGS[@]}")
fi

echo "[INFO] Inventory: $INV_DIR"
echo "[INFO] Playbook : $PLAYBOOK"
echo "[INFO] CMD      : ${cmd[*]}"

"${cmd[@]}"
