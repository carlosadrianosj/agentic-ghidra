#!/usr/bin/env bash
# Start the Agentic-Ghidra supervisor with sane defaults.
#
# Usage:
#   ./run.sh                          # one default worker, supervisor on :29840
#   PORT=9000 ./run.sh                # different supervisor port
#   ./run.sh --config workers.json    # custom worker layout
#   GHIDRA_INSTALL_DIR=/g ./run.sh    # skip Ghidra autodetection
set -euo pipefail

PORT="${PORT:-29840}"
CONFIG="${CONFIG:-runtime/supervisor.json}"

find_ghidra() {
    local candidate
    for candidate in \
        "${GHIDRA_INSTALL_DIR:-}" \
        "$HOME/ghidra" \
        "$HOME"/ghidra_* \
        /opt/ghidra* \
        /Applications/ghidra* \
        /Applications/Ghidra.app/Contents/Resources/ghidra*; do
        if [ -n "$candidate" ] && [ -x "$candidate/support/analyzeHeadless" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

GHIDRA="$(find_ghidra)" || {
    echo "error: Ghidra not found" >&2
    echo "set GHIDRA_INSTALL_DIR to the folder that contains support/analyzeHeadless" >&2
    exit 1
}
export GHIDRA_INSTALL_DIR="$GHIDRA"

command -v uv >/dev/null 2>&1 || {
    echo "error: uv not found, install it from https://docs.astral.sh/uv/" >&2
    exit 1
}

echo "==> Ghidra: $GHIDRA_INSTALL_DIR"
echo "==> Syncing environment"
uv sync --quiet

extra=()
has_port=false
has_config=false
for arg in "$@"; do
    case "$arg" in
        --port|--port=*) has_port=true ;;
        --config|--config=*) has_config=true ;;
    esac
done

if [ "$has_config" = false ]; then
    if [ ! -f "$CONFIG" ]; then
        mkdir -p "$(dirname "$CONFIG")" runtime/projects
        worker_port=$((PORT + 1))
        cat > "$CONFIG" <<EOF
{
  "workers": [
    {
      "worker_id": "main",
      "port": $worker_port,
      "project_path": "projects/main",
      "project_name": "main",
      "max_workers": 1,
      "input_paths": []
    }
  ]
}
EOF
        echo "==> Wrote default config $CONFIG (worker main on port $worker_port)"
    fi
    extra+=(--config "$CONFIG")
fi
[ "$has_port" = true ] || extra+=(--port "$PORT")

echo "==> Supervisor on http://127.0.0.1:$PORT  (MCP at /mcp, REST at /api/v1)"
exec .venv/bin/agentic-ghidra ${extra[@]+"${extra[@]}"} "$@"
