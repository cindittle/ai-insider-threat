# AI Insider Threat Capstone

This repository supports a cybersecurity capstone project focused on AI-assisted SOC detection using simulated log data.

## Project Overview

The project builds a Python-based miniature SIEM-style pipeline that ingests simulated cybersecurity logs, processes and normalizes the data, detects suspicious insider-threat behavior, assigns risk scores, correlates related events, and generates explainable alerts for analyst review.

The primary implementation uses Python and simulated CSV files. Optional SIEM integration with Splunk or Wazuh may be added later if licensing or access becomes available.

## Repository Structure

- `data/` - Simulated CSV log files used for testing
- `docs/` - Architecture diagram, delivery plan, and project documentation
- `notebooks/` - Jupyter notebooks for development and testing
- `src/` - Python scripts for log processing, detection, scoring, and alert generation
- `outputs/` - Generated alerts, risk scores, and risk register outputs

## Simulated Log Data

The project currently includes synthetic log files for:

- Authentication activity
- File access activity
- Endpoint/activity events
- Privilege-use events
- HDR/human-risk events
- Combined log analysis

These logs include normal user behavior, suspicious behavior, and injected suspicious events to support anomaly detection, risk scoring, and event correlation.

## Current Progress

- Architecture diagram completed
- Jira board created and broken into child items
- Initial simulated log files created
- GitHub repository created
- 7-week delivery plan created
- Python processing layer is the next development step

## Next Steps

1. Load CSV files using Python and pandas
2. Parse timestamps and clean missing data
3. Normalize log fields across log types
4. Extract features such as login hour, failed login count, file access volume, device changes, privilege use, and HDR signals
5. Build anomaly detection and rule-based checks
6. Correlate suspicious events
7. Generate explainable alert output
8. Map alerts into a risk-register-style format

## Project Goal

The goal of this project is to demonstrate how AI-assisted analytics can support SOC workflows by identifying suspicious behavior, prioritizing risk, and explaining why an alert was generated.