#!/bin/bash
set -euo pipefail

# Configuration for real solver (adjust for production)
LOG_DIR="./solver_logs_$(date +%Y%m%d_%H%M%S)"
MAX_LOG_SIZE="10M"  # Rotate when file reaches 10MB
CHECK_INTERVAL=300  # Check every 5 minutes (300 seconds)
SOLVER_CONFIG="${1:-config/demo.toml}"

echo "=== REAL SOLVER WITH LOG ROTATION ==="
echo "Config: $SOLVER_CONFIG"
echo "Log rotation at: $MAX_LOG_SIZE"
echo "Check interval: ${CHECK_INTERVAL}s"
echo "Press Ctrl+C to stop"
echo "====================================="

# Create log directory with timestamp
mkdir -p "$LOG_DIR"

# Create a summary file for easy reference
SUMMARY_FILE="$LOG_DIR/session_summary.txt"

# Function to get file size in bytes
get_file_size() {
    if [ -f "$1" ]; then
        stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# Function to convert size string to bytes
size_to_bytes() {
    local size="$1"
    local number=$(echo "$size" | sed 's/[^0-9.]//g')
    local unit=$(echo "$size" | sed 's/[0-9.]//g' | tr '[:lower:]' '[:upper:]')
    
    case "$unit" in
        "K"|"KB") echo "$((${number%.*} * 1024))" ;;
        "M"|"MB") echo "$((${number%.*} * 1024 * 1024))" ;;
        "G"|"GB") echo "$((${number%.*} * 1024 * 1024 * 1024))" ;;
        "") echo "${number%.*}" ;;
        *) echo "${number%.*}" ;;
    esac
}

# Function to convert bytes to human readable format
bytes_to_human() {
    local bytes="$1"
    if [ "$bytes" -ge 1073741824 ]; then
        echo "$((bytes / 1073741824))G"
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$((bytes / 1048576))M"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$((bytes / 1024))K"
    else
        echo "${bytes}B"
    fi
}

# Function to rotate logs (NO DELETION)
rotate_log() {
    local current_log="$1"
    if [ -f "$current_log" ]; then
        local timestamp=$(date +%Y%m%d_%H%M%S)
        local sequence=$(printf "%04d" $((ROTATION_COUNT++)))
        local rotated_log="$LOG_DIR/solver_${sequence}_${timestamp}.log"
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ROTATION] Rotating log file to $rotated_log"
        mv "$current_log" "$rotated_log"
        
        # Compress in background to save space
        gzip "$rotated_log" &
        
        # Update summary
        update_summary "$rotated_log.gz"
    fi
}

# Function to update session summary
update_summary() {
    local log_file="$1"
    local file_size=$(get_file_size "${log_file%%.gz}")  # Size before compression
    
    cat >> "$SUMMARY_FILE" << EOF
Log File: $(basename "$log_file")
Created: $(date '+%Y-%m-%d %H:%M:%S')
Original Size: $(bytes_to_human "$file_size")
---
EOF
}

# Function to monitor log size and rotate if needed
monitor_log_size() {
    local current_log="$1"
    local max_size_bytes=$(size_to_bytes "$MAX_LOG_SIZE")
    
    while true; do
        if [ -f "$current_log" ]; then
            local current_size=$(get_file_size "$current_log")
            # Ensure current_size is a number and greater than 0
            if [ -n "$current_size" ] && [ "$current_size" -gt 0 ] 2>/dev/null && [ "$current_size" -gt "$max_size_bytes" ]; then
                echo "[ROTATION] Log size $current_size bytes exceeds limit $max_size_bytes bytes"
                rotate_log "$current_log"
            fi
        fi
        sleep "$CHECK_INTERVAL"
    done
}

# Function to generate final report
generate_final_report() {
    local report_file="$LOG_DIR/final_report.txt"
    local session_end=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > "$report_file" << EOF
=== SOLVER RUN FINAL REPORT ===
Session Start: $SESSION_START
Session End: $session_end
Total Duration: $(($(date +%s) - START_TIMESTAMP)) seconds

Config Used: $SOLVER_CONFIG
Log Directory: $LOG_DIR
Total Log Files: $(ls -1 "$LOG_DIR"/solver_*.log.gz 2>/dev/null | wc -l)
Total Compressed Size: $(du -sh "$LOG_DIR" | cut -f1)

Log Files Generated:
EOF
    
    # List all log files with details
    ls -lah "$LOG_DIR"/solver_*.log.gz 2>/dev/null | while read -r line; do
        echo "  $line" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF

Results:
- Log rotation: $([ $(ls -1 "$LOG_DIR"/solver_*.log.gz 2>/dev/null | wc -l) -gt 0 ] && echo "SUCCESS" || echo "NO ROTATION NEEDED")
- Compression: $([ -f "$LOG_DIR"/solver_*.log.gz ] && echo "SUCCESS" || echo "NO FILES TO COMPRESS")
- Summary file: $([ -f "$SUMMARY_FILE" ] && echo "SUCCESS" || echo "FAILED")

Analysis Commands:
# View all logs chronologically:
zcat $LOG_DIR/solver_*.log.gz | sort

# Search for errors:
zcat $LOG_DIR/solver_*.log.gz | grep -i error

# Count log levels:
zcat $LOG_DIR/solver_*.log.gz | grep -c "INFO"
zcat $LOG_DIR/solver_*.log.gz | grep -c "ERROR"
zcat $LOG_DIR/solver_*.log.gz | grep -c "WARN"
zcat $LOG_DIR/solver_*.log.gz | grep -c "DEBUG"

=== END REPORT ===
EOF
    
    echo "Final report generated: $report_file"
}

# Function to handle graceful shutdown
cleanup_and_exit() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SHUTDOWN] Solver session ending..."
    
    # Kill background processes
    [ -n "${MONITOR_PID:-}" ] && kill "$MONITOR_PID" 2>/dev/null || true
    [ -n "${SOLVER_PID:-}" ] && kill "$SOLVER_PID" 2>/dev/null || true
    
    # Final log rotation
    rotate_log "$CURRENT_LOG"
    
    # Generate final report
    generate_final_report
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SHUTDOWN] All logs preserved in: $LOG_DIR"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SHUTDOWN] Total log files: $(ls -1 "$LOG_DIR"/solver_*.log.gz 2>/dev/null | wc -l)"
    
    # Show results
    echo ""
    echo "=== SESSION RESULTS ==="
    echo "Log directory: $LOG_DIR"
    echo "Files created: $(ls -1 "$LOG_DIR"/ | wc -l)"
    echo "Compressed logs: $(ls -1 "$LOG_DIR"/solver_*.log.gz 2>/dev/null | wc -l)"
    echo "Total size: $(du -sh "$LOG_DIR" | cut -f1)"
    
    if [ -f "$LOG_DIR/final_report.txt" ]; then
        echo ""
        echo "View the full report with:"
        echo "cat $LOG_DIR/final_report.txt"
    fi
    
    exit 0
}

# Set up signal handlers
trap cleanup_and_exit SIGTERM SIGINT

# Initialize variables
ROTATION_COUNT=1
SESSION_START=$(date '+%Y-%m-%d %H:%M:%S')
START_TIMESTAMP=$(date +%s)
CURRENT_LOG="$LOG_DIR/solver_current.log"

# Create initial summary
cat > "$SUMMARY_FILE" << EOF
=== SOLVER SESSION ===
Started: $SESSION_START
Config: $SOLVER_CONFIG
Log Directory: $LOG_DIR
Max Log Size: $MAX_LOG_SIZE
Rotation Check Interval: ${CHECK_INTERVAL}s

ALL LOG FILES ARE PRESERVED - NO AUTOMATIC DELETION

Log Files:
EOF

echo "=== Solver Session Started: $SESSION_START ===" | tee -a "$CURRENT_LOG"
echo "Config: $SOLVER_CONFIG" | tee -a "$CURRENT_LOG"
echo "Log Directory: $LOG_DIR" | tee -a "$CURRENT_LOG"
echo "Max Log Size: $MAX_LOG_SIZE" | tee -a "$CURRENT_LOG"
echo "=============================================" | tee -a "$CURRENT_LOG"

# Start log size monitoring in background
monitor_log_size "$CURRENT_LOG" &
MONITOR_PID=$!

# Start the real solver
echo "$(date '+%Y-%m-%d %H:%M:%S') [START] Starting OIF Solver..." | tee -a "$CURRENT_LOG"

# Run the actual solver with proper error handling
if cargo run --bin solver -- --config "$SOLVER_CONFIG" --log-level debug 2>&1 | \
   while IFS= read -r line; do
       echo "$(date '+%Y-%m-%d %H:%M:%S') $line" | tee -a "$CURRENT_LOG"
   done; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [END] Solver completed successfully" | tee -a "$CURRENT_LOG"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Solver exited with error code $?" | tee -a "$CURRENT_LOG"
fi

# Cleanup
cleanup_and_exit