#!/bin/bash
# Download monitoring.py (or use local if available), set up PYTHONPATH, and run the given script

if [ $# -ne 1 ]; then
    echo "Usage: $0 <python_script>"
    exit 1
fi

SCRIPT=$1
MONITORING_LOCAL="src/py/monitoring.py"
MONITORING_URL="https://raw.githubusercontent.com/sebastien/monitoring/main/src/py/monitoring.py"

if [ -f "$MONITORING_LOCAL" ]; then
    # Use local file
    MONITORING_DIR="src/py"
    MONITORING_PATH="$MONITORING_DIR/monitoring.py"
else
    # Download to temp
    TEMP_DIR=$(mktemp -d)
    curl -s -o "$TEMP_DIR/monitoring.py" "$MONITORING_URL" || { echo "Failed to download monitoring.py"; exit 1; }
    MONITORING_PATH="$TEMP_DIR/monitoring.py"
fi

echo "MONITORING_PATH: $MONITORING_PATH"

MONITORING_PATH_DIR="$(dirname "$MONITORING_PATH")"

# Set PYTHONPATH
export PYTHONPATH="$MONITORING_PATH_DIR"

# Run the script
python -c "import os; print('Env PYTHONPATH:', repr(os.environ.get('PYTHONPATH')))"
python "$SCRIPT"