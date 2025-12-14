#!/bin/bash

set -e

# Paths
BASEDIR=$(dirname "$(readlink -f "$0")")
OUTDIR=$(dirname "$BASEDIR")
OUT_FOLDER="$OUTDIR/ebpf_out"
PID_FILE="$OUT_FOLDER/ebpf_monitor.pid"

# Printing helpers
info()    { echo -e "\e[34m[*]\e[0m $1"; }
success() { echo -e "\e[32m[+]\e[0m $1"; }
error()   { echo -e "\e[31m[!]\e[0m $1"; }

echo "=============================================="
echo "          Stopping eBPF Monitoring"
echo "=============================================="

# Sanity checks
if [ ! -d "$OUT_FOLDER" ]; then
    error "Output folder not found: $OUT_FOLDER"
    exit 1
fi

if [ ! -f "$PID_FILE" ]; then
    error "PID file missing: $PID_FILE"
    echo "[!] Attempting to detect monitor process automatically..."
    MONITOR_PID=$(pgrep -f "ebpf_monitor.py" || true)

    if [ -z "$MONITOR_PID" ]; then
        error "Could not detect any running monitor."
        exit 1
    else
        echo "$MONITOR_PID" > "$PID_FILE"
        success "Recovered PID: $MONITOR_PID"
    fi
fi

MONITOR_PID=$(cat "$PID_FILE")

# Stop the monitor
if ps -p "$MONITOR_PID" > /dev/null 2>&1; then
    info "Stopping eBPF monitor (PID: $MONITOR_PID)..."
    kill -TERM "$MONITOR_PID"

    sleep 2

    if ps -p "$MONITOR_PID" > /dev/null 2>&1; then
        info "Process still running — forcing kill..."
        kill -9 "$MONITOR_PID"
        sleep 1
    fi

    success "eBPF monitor stopped successfully."
else
    info "Monitor process not running."
fi

rm -f "$PID_FILE"

# Capture final system state
info "Capturing final system state..."

FINAL_STATE="$OUT_FOLDER/final_state"
mkdir -p "$FINAL_STATE"

ps -ef               > "$FINAL_STATE/processes.txt"
lsof -i -n -P        > "$FINAL_STATE/sockets.txt" 2>/dev/null
netstat -tulpn       > "$FINAL_STATE/netstat.txt" 2>/dev/null

# Count events
if [ -f "$OUT_FOLDER/ebpf_events.jsonl" ]; then
    EVENT_COUNT=$(wc -l < "$OUT_FOLDER/ebpf_events.jsonl")
    success "Total events captured: $EVENT_COUNT"
else
    error "No ebpf_events.jsonl found — monitor may not have run."
fi

# Fix permissions
info "Fixing permissions so Streamlit can read all files..."

if [ -n "$SUDO_USER" ]; then
    chown -R "$SUDO_USER":"$SUDO_USER" "$OUT_FOLDER"
fi

success "Permissions updated."

echo ""
success "eBPF monitoring stopped and data preserved in:"
echo "  $OUT_FOLDER"
echo "Event log:"
echo "  $OUT_FOLDER/ebpf_events.jsonl"
echo ""
