#!/bin/bash

# Rivals Analysis Data Cleanup Script
# This script cleans up old analysis data based on retention policies

set -e

RIVALS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$RIVALS_DIR/config/data-sources.json"

echo "🧹 Starting rivals analysis data cleanup..."
echo "📁 Rivals directory: $RIVALS_DIR"

# Check if jq is installed for JSON parsing
if ! command -v jq &> /dev/null; then
    echo "❌ Error: jq is required but not installed. Please install jq first."
    exit 1
fi

# Read retention settings from config
if [ -f "$CONFIG_FILE" ]; then
    RAW_DATA_MONTHS=$(jq -r '.collection_settings.data_retention.raw_data_months' "$CONFIG_FILE")
    AGGREGATED_DATA_MONTHS=$(jq -r '.collection_settings.data_retention.aggregated_data_months' "$CONFIG_FILE")
    REPORTS_MONTHS=$(jq -r '.collection_settings.data_retention.reports_months' "$CONFIG_FILE")
else
    echo "⚠️  Warning: Config file not found. Using default retention periods."
    RAW_DATA_MONTHS=6
    AGGREGATED_DATA_MONTHS=24
    REPORTS_MONTHS=36
fi

echo "📅 Retention policies:"
echo "   Raw data: $RAW_DATA_MONTHS months"
echo "   Aggregated data: $AGGREGATED_DATA_MONTHS months"
echo "   Reports: $REPORTS_MONTHS months"

# Calculate cutoff dates
RAW_DATA_CUTOFF=$(date -d "$RAW_DATA_MONTHS months ago" +%Y-%m-%d)
AGGREGATED_DATA_CUTOFF=$(date -d "$AGGREGATED_DATA_MONTHS months ago" +%Y-%m-%d)
REPORTS_CUTOFF=$(date -d "$REPORTS_MONTHS months ago" +%Y-%m-%d)

echo "🗓️  Cutoff dates:"
echo "   Raw data: $RAW_DATA_CUTOFF"
echo "   Aggregated data: $AGGREGATED_DATA_CUTOFF"
echo "   Reports: $REPORTS_CUTOFF"

# Cleanup functions
cleanup_old_files() {
    local dir="$1"
    local cutoff_date="$2"
    local description="$3"
    
    if [ ! -d "$dir" ]; then
        echo "📂 Directory $dir does not exist, skipping."
        return
    fi
    
    echo "🔍 Cleaning up $description in $dir (older than $cutoff_date)..."
    
    # Find and remove files older than cutoff date
    find "$dir" -name "*.json" -type f -exec stat -c '%Y %n' {} \; | \
    while read timestamp filename; do
        file_date=$(date -d "@$timestamp" +%Y-%m-%d)
        if [[ "$file_date" < "$cutoff_date" ]]; then
            echo "🗑️  Removing old file: $filename (from $file_date)"
            rm -f "$filename"
        fi
    done
}

# Clean up historical data
cleanup_old_files "$RIVALS_DIR/historical/daily" "$RAW_DATA_CUTOFF" "daily raw data"
cleanup_old_files "$RIVALS_DIR/historical/weekly" "$AGGREGATED_DATA_CUTOFF" "weekly aggregated data"
cleanup_old_files "$RIVALS_DIR/historical/monthly" "$REPORTS_CUTOFF" "monthly reports"

# Clean up old comparison reports
cleanup_old_files "$RIVALS_DIR/comparisons" "$REPORTS_CUTOFF" "comparison reports"

# Clean up company analysis data (keep only recent)
if [ -d "$RIVALS_DIR/companies" ]; then
    echo "🔍 Cleaning up old company analysis data..."
    for company_dir in "$RIVALS_DIR/companies"/*; do
        if [ -d "$company_dir" ]; then
            cleanup_old_files "$company_dir/website-analysis" "$RAW_DATA_CUTOFF" "website analysis"
            cleanup_old_files "$company_dir/social-media" "$AGGREGATED_DATA_CUTOFF" "social media data"
            cleanup_old_files "$company_dir/market-data" "$AGGREGATED_DATA_CUTOFF" "market data"
        fi
    done
fi

# Remove empty directories
echo "📁 Removing empty directories..."
find "$RIVALS_DIR" -type d -empty -delete 2>/dev/null || true

# Generate cleanup report
CLEANUP_REPORT="$RIVALS_DIR/cleanup-report-$(date +%Y%m%d-%H%M%S).log"
echo "📊 Generating cleanup report: $CLEANUP_REPORT"

cat > "$CLEANUP_REPORT" << EOF
Rivals Analysis Data Cleanup Report
Generated: $(date)

Retention Policies Applied:
- Raw data retention: $RAW_DATA_MONTHS months
- Aggregated data retention: $AGGREGATED_DATA_MONTHS months  
- Reports retention: $REPORTS_MONTHS months

Cutoff Dates:
- Raw data: $RAW_DATA_CUTOFF
- Aggregated data: $AGGREGATED_DATA_CUTOFF
- Reports: $REPORTS_CUTOFF

Directories Cleaned:
- Historical daily data
- Historical weekly data
- Historical monthly reports
- Comparison reports
- Company analysis data

Status: Cleanup completed successfully
EOF

echo "✅ Data cleanup completed successfully!"
echo "📋 Cleanup report saved to: $CLEANUP_REPORT"

# Optional: Archive cleanup report
if [ "$1" = "--archive-report" ]; then
    ARCHIVE_DIR="$RIVALS_DIR/historical/cleanup-reports"
    mkdir -p "$ARCHIVE_DIR"
    cp "$CLEANUP_REPORT" "$ARCHIVE_DIR/"
    echo "📦 Cleanup report archived to: $ARCHIVE_DIR/"
fi

echo "🎉 Rivals data cleanup completed!"