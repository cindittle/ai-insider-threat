from pathlib import Path
import pandas as pd
import numpy as np

DATA_DIR = Path("data")
OUTPUT_DIR = Path("outputs")

LOG_FILES = {
    "authentication": "simulated_authentication_logs.csv",
    "file_access": "simulated_file_access_logs.csv",
    "endpoint_activity": "simulated_endpoint_activity_logs.csv",
    "privilege_use": "simulated_privilege_use_logs.csv",
    "hdr_human_risk": "simulated_hdr_human_risk_logs.csv",
}

EXPECTED_COLUMNS = [
    "event_id",
    "timestamp",
    "log_type",
    "user",
    "department",
    "device",
    "source_ip",
    "action",
    "status",
    "resource",
    "risk_signal",
    "severity",
    "label",
    "incident_id",
    "details",
]

SEVERITY_SCORE = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def load_csv_logs(data_dir: Path = DATA_DIR) -> dict[str, pd.DataFrame]:
    """Load each simulated CSV log file into a pandas DataFrame."""
    loaded_logs = {}

    for log_name, file_name in LOG_FILES.items():
        file_path = data_dir / file_name
        if not file_path.exists():
            raise FileNotFoundError(f"Missing required file: {file_path}")

        df = pd.read_csv(file_path)
        loaded_logs[log_name] = df
        print(f"Loaded {file_name}: {len(df)} rows")

    return loaded_logs


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Standardize column names and make sure expected columns exist."""
    cleaned = df.copy()
    cleaned.columns = [col.strip().lower().replace(" ", "_") for col in cleaned.columns]

    for col in EXPECTED_COLUMNS:
        if col not in cleaned.columns:
            cleaned[col] = np.nan

    return cleaned[EXPECTED_COLUMNS]


def clean_log_data(df: pd.DataFrame) -> pd.DataFrame:
    """Parse timestamps, clean missing values, and create useful time fields."""
    cleaned = normalize_columns(df)

    # Parse timestamp field
    cleaned["timestamp"] = pd.to_datetime(cleaned["timestamp"], errors="coerce")

    # Remove rows without the fields needed for detection
    cleaned = cleaned.dropna(subset=["event_id", "timestamp", "user", "log_type"])

    # Normalize text fields for consistency
    text_columns = [
        "log_type", "user", "department", "device", "source_ip", "action",
        "status", "resource", "risk_signal", "severity", "label", "incident_id", "details"
    ]

    for col in text_columns:
        cleaned[col] = cleaned[col].fillna("none").astype(str).str.strip()

    # Standardize important categories
    cleaned["log_type"] = cleaned["log_type"].str.lower().str.replace(" ", "_")
    cleaned["action"] = cleaned["action"].str.lower().str.replace(" ", "_")
    cleaned["status"] = cleaned["status"].str.lower()
    cleaned["severity"] = cleaned["severity"].str.lower()
    cleaned["label"] = cleaned["label"].str.lower()
    cleaned["risk_signal"] = cleaned["risk_signal"].str.lower().str.replace(" ", "_")

    # Create time-based features for later anomaly detection
    cleaned["date"] = cleaned["timestamp"].dt.date
    cleaned["hour"] = cleaned["timestamp"].dt.hour
    cleaned["day_of_week"] = cleaned["timestamp"].dt.day_name()
    cleaned["is_weekend"] = cleaned["timestamp"].dt.day_of_week >= 5
    cleaned["is_after_hours"] = (cleaned["hour"] < 7) | (cleaned["hour"] > 18)

    # Create numeric severity score for later risk scoring
    cleaned["severity_score"] = cleaned["severity"].map(SEVERITY_SCORE).fillna(0).astype(int)

    return cleaned


def merge_related_logs(cleaned_logs: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Combine all cleaned logs into one timeline-style dataset."""
    combined = pd.concat(cleaned_logs.values(), ignore_index=True)
    combined = combined.sort_values(["user", "timestamp", "event_id"]).reset_index(drop=True)

    # Event order per user helps with later correlation logic
    combined["user_event_sequence"] = combined.groupby("user").cumcount() + 1

    # Flag whether event is part of a known injected incident
    combined["has_incident_id"] = combined["incident_id"].ne("none")

    return combined


def create_user_event_summary(combined: pd.DataFrame) -> pd.DataFrame:
    """Create a simple user-level summary for validation and later detection work."""
    summary = (
        combined.groupby("user")
        .agg(
            total_events=("event_id", "count"),
            first_event=("timestamp", "min"),
            last_event=("timestamp", "max"),
            after_hours_events=("is_after_hours", "sum"),
            suspicious_events=("label", lambda x: (x != "normal").sum()),
            incident_events=("has_incident_id", "sum"),
            max_severity_score=("severity_score", "max"),
        )
        .reset_index()
        .sort_values(["suspicious_events", "after_hours_events", "total_events"], ascending=False)
    )

    return summary


def save_outputs(combined: pd.DataFrame, summary: pd.DataFrame, output_dir: Path = OUTPUT_DIR) -> None:
    """Save cleaned outputs to the outputs folder."""
    output_dir.mkdir(exist_ok=True)

    combined_path = output_dir / "cleaned_all_logs.csv"
    summary_path = output_dir / "user_event_summary.csv"

    combined.to_csv(combined_path, index=False)
    summary.to_csv(summary_path, index=False)

    print(f"Saved cleaned dataset: {combined_path}")
    print(f"Saved user summary: {summary_path}")


def main() -> None:
    print("Starting Python processing layer...")

    raw_logs = load_csv_logs(DATA_DIR)
    cleaned_logs = {name: clean_log_data(df) for name, df in raw_logs.items()}
    combined = merge_related_logs(cleaned_logs)
    summary = create_user_event_summary(combined)
    save_outputs(combined, summary, OUTPUT_DIR)

    print("Processing complete.")
    print(f"Total cleaned rows: {len(combined)}")
    print(f"Total users: {combined['user'].nunique()}")
    print(f"Total suspicious/non-normal events: {(combined['label'] != 'normal').sum()}")


if __name__ == "__main__":
    main()
