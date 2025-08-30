# Rivals Analysis Directory

This directory contains sensitive competitor analysis data and is excluded from version control.

## Directory Structure

```
rivals/
├── companies/          # Individual company analysis data
│   ├── {company-name}/
│   │   ├── profile.json
│   │   ├── website-analysis/
│   │   ├── social-media/
│   │   └── market-data/
├── sectors/            # Sector-specific analysis
│   ├── {sector-name}/
│   │   ├── overview.json
│   │   ├── companies.json
│   │   └── trends/
├── comparisons/        # Comparative analysis results
│   ├── {comparison-id}/
│   │   ├── metadata.json
│   │   ├── companies.json
│   │   └── report.json
├── historical/         # Time-series analysis data
│   ├── daily/
│   ├── weekly/
│   └── monthly/
├── templates/          # Report templates
│   ├── company-profile.json
│   ├── sector-analysis.json
│   └── comparison-report.json
├── config/            # Analysis configuration
│   ├── sectors.json
│   ├── data-sources.json
│   └── analysis-rules.json
└── scripts/           # Utility scripts
    ├── data-cleanup.sh
    ├── export-reports.sh
    └── sync-data.sh
```

## Usage

### Company Analysis Data
Store individual company analysis results in `companies/{company-name}/`:
- `profile.json`: Company basic information
- `website-analysis/`: Website analysis results
- `social-media/`: Social media analysis
- `market-data/`: Market positioning and financial data

### Sector Analysis
Group related companies by sector in `sectors/{sector-name}/`:
- `overview.json`: Sector overview and trends
- `companies.json`: List of companies in sector
- `trends/`: Historical trend data

### Comparisons
Store comparative analysis in `comparisons/{comparison-id}/`:
- `metadata.json`: Comparison parameters and settings
- `companies.json`: Companies being compared
- `report.json`: Comparison results and insights

### Historical Data
Archive time-series data in `historical/`:
- `daily/`: Daily snapshots
- `weekly/`: Weekly aggregations
- `monthly/`: Monthly reports

## Data Format

All data files use JSON format with standardized schemas. See templates/ directory for examples.

## Security

- This directory is excluded from git
- Contains sensitive competitor intelligence
- Should be encrypted in production
- Access should be restricted to authorized personnel only