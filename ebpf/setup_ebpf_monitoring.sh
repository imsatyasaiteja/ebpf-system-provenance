#!/bin/bash

set -e

# Paths
BASEDIR=$(dirname "$(readlink -f "$0")")
OUTDIR=$(dirname "$BASEDIR")
MONITOR_SCRIPT="$BASEDIR/ebpf_monitor.py"
OUT_FOLDER="$OUTDIR/ebpf_out"
CONFIG_FILE="$OUTDIR/conf/config.json"

# Printing helpers
info()    { echo -e "\e[34m[*]\e[0m $1"; }
success() { echo -e "\e[32m[+]\e[0m $1"; }
error()   { echo -e "\e[31m[!]\e[0m $1"; }

echo "=============================================="
echo "        eBPF Monitoring Setup"
echo "=============================================="

# Require root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (sudo)."
    exit 1
fi

# Check Python3
if ! command -v python3 &>/dev/null; then
    error "python3 not found — install Python 3."
    exit 1
fi

# Check BCC
info "Checking BCC installation..."
if ! python3 -c "import bcc" 2>/dev/null; then
    error "BCC Python bindings missing. Installing..."
    apt-get update
    apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
else
    success "BCC is installed."
fi

# Prepare output folder
info "Setting up output directory: $OUT_FOLDER"
rm -rf "$OUT_FOLDER"
mkdir -p "$OUT_FOLDER"

# Ensure config exists
if [ ! -f "$CONFIG_FILE" ]; then
    error "Config file missing: $CONFIG_FILE"
    exit 1
fi

# Capture baseline
info "Collecting baseline system information..."

mkdir -p "$OUT_FOLDER/procinfo" "$OUT_FOLDER/fdinfo" "$OUT_FOLDER/socketinfo"

ps -ef        > "$OUT_FOLDER/procinfo/general.txt"
ps -eo pid    > "$OUT_FOLDER/procinfo/pid.txt"
ps -eo comm   > "$OUT_FOLDER/procinfo/exe.txt"
ps -eo args   > "$OUT_FOLDER/procinfo/args.txt"
ps -eo ppid   > "$OUT_FOLDER/procinfo/ppid.txt"

for p in /proc/[0-9]*; do
    pid=$(basename "$p")
    ls -la "/proc/$pid/fd" > "$OUT_FOLDER/fdinfo/$pid" 2>/dev/null || true
done

lsof -i -n -P > "$OUT_FOLDER/socketinfo/general.txt" 2>/dev/null
awk '{print $6}' "$OUT_FOLDER/socketinfo/general.txt" > "$OUT_FOLDER/socketinfo/device.txt"
awk '{print $9}' "$OUT_FOLDER/socketinfo/general.txt" > "$OUT_FOLDER/socketinfo/name.txt"

success "Baseline snapshot collected."

# Start eBPF monitor
info "Starting eBPF monitor..."

LOG_FILE="$OUT_FOLDER/ebpf_events.jsonl"
PID_FILE="$OUT_FOLDER/ebpf_monitor.pid"

chmod +x "$MONITOR_SCRIPT"

# Start monitor in background (unbuffered stdout for consistent logging)
nohup python3 -u "$MONITOR_SCRIPT" --config "$CONFIG_FILE" > "$OUT_FOLDER/monitor.log" 2>&1 &
PID=$!

# Allow monitor time to initialize (prevents PID race-condition)
sleep 1

# Check if running
if ! ps -p "$PID" >/dev/null 2>&1; then
    error "Monitor crashed on startup. Check monitor.log:"
    echo ""
    tail -20 "$OUT_FOLDER/monitor.log"
    exit 1
fi

# Write PID (guaranteed)
echo "$PID" > "$PID_FILE"
success "eBPF monitor is running (PID: $PID)"

# Fix permissions for Streamlit compatibility
info "Fixing permissions so Streamlit can access logs..."
if [ -n "$SUDO_USER" ]; then
    chown -R "$SUDO_USER":"$SUDO_USER" "$OUT_FOLDER"
fi

echo ""
success "Setup complete."
echo "[*] Event Log: $LOG_FILE"
echo "[*] Stop using: stop_ebpf_monitoring.sh"