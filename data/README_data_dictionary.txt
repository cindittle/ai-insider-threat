Capstone Simulated Log Inputs

Purpose:
These CSV files are simulated SOC-style logs for a Python-based insider-threat / suspicious-event detection prototype. They are fake data and do not contain real user activity.

Included files:
1. simulated_authentication_logs.csv
2. simulated_file_access_logs.csv
3. simulated_endpoint_activity_logs.csv
4. simulated_privilege_use_logs.csv
5. simulated_hdr_human_risk_logs.csv
6. simulated_all_logs_combined.csv

Shared fields:
- event_id: Unique ID for each event
- timestamp: Event date/time
- log_type: Source category of the log
- user: Simulated user account
- department: Simulated department
- device: Simulated endpoint/device name
- source_ip: Simulated source IP address
- action: Event action
- status: Event outcome
- resource: System, file, portal, or process involved
- risk_signal: Risk indicator(s), such as after_hours, failed_login, new_device, abnormal_file_volume, HDR signal
- severity: low, medium, or high
- label: normal or suspicious
- incident_id: Shared ID for correlated suspicious events
- details: Plain-English explanation of event meaning

Injected suspicious event:
INC-001 centers on user m.chen. The incident includes human-risk/HDR behavior, failed after-hours login attempts, successful login from an unknown device, abnormal file downloads, suspicious endpoint activity, and privilege-use activity.

How this supports the Jira task:
- Creates separate simulated CSV log inputs
- Includes normal behavior examples
- Includes suspicious user behavior examples
- Includes injected suspicious events
- Uses consistent fields across each CSV
