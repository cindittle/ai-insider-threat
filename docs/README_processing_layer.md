# Python Processing Layer

This folder contains the first Python script for the capstone project.

## Jira task supported

Build Python processing layer

## What this script does

The script `src/log_processing.py` supports these child items:

- Set up Python environment
- Import pandas/NumPy
- Load CSV logs
- Parse timestamps
- Clean missing data
- Normalize log fields
- Merge related logs
- Create cleaned dataset

## How to run

From the project root folder, run:

```bash
python src/log_processing.py
```

## Expected input files

The script expects these files in the `data/` folder:

- `simulated_authentication_logs.csv`
- `simulated_file_access_logs.csv`
- `simulated_endpoint_activity_logs.csv`
- `simulated_privilege_use_logs.csv`
- `simulated_hdr_human_risk_logs.csv`

## Output files

The script creates these files in the `outputs/` folder:

- `cleaned_all_logs.csv`
- `user_event_summary.csv`

## Purpose

This processing layer prepares the simulated SOC logs for the next project stage: anomaly detection, behavior baseline comparison, risk scoring, and explainable alert generation.
