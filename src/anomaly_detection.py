"""SOC behavioral analytics and anomaly detection using synthetic security logs.

Run from the repository root after completing log preprocessing:
    python src/log_processing.py
    python src/anomaly_detection.py

The detector never reads ground-truth columns (label, incident_id, severity,
risk_signal, details) when deciding whether to flag an event. Those columns
are used only by a separate test-report calculation at the end.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "outputs" / "cleaned_all_logs.csv"
DEFAULT_OUTPUT = ROOT / "outputs"
BUSINESS_START_HOUR = 7
BUSINESS_END_HOUR = 19  # 19:00 onward is after hours
ML_FEATURES = [
    "auth_failures", "after_hours_logins", "unique_login_devices",
    "file_downloads", "file_access_events", "privilege_events",
    "hdr_events", "endpoint_events",
]


def load_detection_input(path: Path) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing cleaned logs at {path}. Run 'python src/log_processing.py' first."
        )
    df = pd.read_csv(path, parse_dates=["timestamp"])
    required = {"event_id", "timestamp", "user", "log_type", "action", "status", "device", "resource"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"Cleaned input is missing columns: {missing}")
    if df["timestamp"].isna().any():
        raise ValueError("Cleaned input contains unparseable timestamps.")
    if df["event_id"].duplicated().any():
        raise ValueError("Duplicate event_id values: cannot safely correlate events.")
    df = df.sort_values(["timestamp", "event_id"]).reset_index(drop=True)
    for col in ["user", "log_type", "action", "status", "device", "resource"]:
        df[col] = df[col].fillna("").astype(str).str.strip().str.lower()
    df["date"] = df["timestamp"].dt.strftime("%Y-%m-%d")
    df["hour"] = df["timestamp"].dt.hour
    return df


def split_training_days(df: pd.DataFrame, baseline_days: int = 7) -> tuple[pd.DataFrame, str]:
    """Use only the first N distinct days (chronologically), never labels."""
    dates = sorted(df["date"].unique().tolist())
    if baseline_days < 2:
        raise ValueError("Require at least two baseline days.")
    if len(dates) <= baseline_days:
        raise ValueError("Need at least one evaluation day after baseline days.")
    last_training_date = dates[baseline_days - 1]
    return df.loc[df["date"] <= last_training_date].copy(), last_training_date


def make_user_baselines(training: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Learn observed normal-era devices, login times and daily downloads."""
    baselines = []
    lookup = {}
    for user, g in training.groupby("user", sort=True):
        logins = g.loc[(g.log_type == "authentication") & (g.action == "login") & (g.status == "success")]
        login_hours = logins.timestamp.dt.hour + logins.timestamp.dt.minute / 60
        devices = sorted({str(x) for x in logins.device if str(x) not in ("", "none", "nan")})
        files = g[(g.log_type == "file_access") & (g.action == "download")]
        counts = files.groupby("date").size()
        max_daily_downloads = int(counts.max()) if len(counts) else 0
        average = float(login_hours.mean()) if len(login_hours) else 12.0
        deviation = float(login_hours.std(ddof=0)) if len(login_hours) > 1 else 1.0
        row = {
            "user": user,
            "training_login_count": int(len(logins)),
            "normal_login_hour_mean": round(average, 3),
            "normal_login_hour_std": round(deviation, 3),
            "known_login_devices": json.dumps(devices),
            "baseline_max_daily_downloads": max_daily_downloads,
            "download_burst_threshold": max(4, max_daily_downloads + 2),
        }
        baselines.append(row)
        lookup[user] = {**row, "device_set": set(devices)}
    return pd.DataFrame(baselines), lookup


def rolling_event_counts(df: pd.DataFrame, mask: pd.Series, window: str) -> dict[str, int]:
    """Rolling event counts including current event, separately for each user."""
    values = {}
    selected = df.loc[mask, ["event_id", "user", "timestamp"]]
    for _user, group in selected.groupby("user"):
        group = group.sort_values(["timestamp", "event_id"])
        frame = group.set_index("timestamp")
        counts = frame["event_id"].rolling(window, min_periods=1).count().astype(int).tolist()
        values.update(zip(group["event_id"].tolist(), counts))
    return values


def make_daily_features(df: pd.DataFrame) -> pd.DataFrame:
    """User-day numeric behavior only; do not inspect synthetic labels."""
    x = df.copy()
    x["auth_failures"] = ((x.log_type == "authentication") & (x.action == "login") & (x.status == "failed")).astype(int)
    x["after_hours_logins"] = ((x.log_type == "authentication") & (x.action == "login") &
                                ((x.hour < BUSINESS_START_HOUR) | (x.hour >= BUSINESS_END_HOUR))).astype(int)
    x["file_downloads"] = ((x.log_type == "file_access") & (x.action == "download")).astype(int)
    for col, log_type in [("file_access_events", "file_access"), ("privilege_events", "privilege_use"),
                          ("hdr_events", "hdr_human_risk"), ("endpoint_events", "endpoint_activity")]:
        x[col] = (x.log_type == log_type).astype(int)
    x["device_for_login"] = x.device.where(
        (x.log_type == "authentication") & (x.action == "login") & (x.status == "success"), np.nan)
    daily = (x.groupby(["user", "date"], as_index=False)
             .agg(auth_failures=("auth_failures", "sum"),
                  after_hours_logins=("after_hours_logins", "sum"),
                  unique_login_devices=("device_for_login", "nunique"),
                  file_downloads=("file_downloads", "sum"),
                  file_access_events=("file_access_events", "sum"),
                  privilege_events=("privilege_events", "sum"),
                  hdr_events=("hdr_events", "sum"),
                  endpoint_events=("endpoint_events", "sum")))
    return daily


def run_ml_daily_anomaly(daily: pd.DataFrame, baseline_end: str) -> pd.DataFrame:
    """IsolationForest trained on prior user-days, not on test labels."""
    train = daily.loc[daily.date <= baseline_end, ML_FEATURES]
    if len(train) < 12:
        raise ValueError("Too few training user-days for a meaningful ML demonstration.")
    scaler = StandardScaler().fit(train)
    model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
    model.fit(scaler.transform(train))
    out = daily.copy()
    out["ml_anomaly_score"] = np.round(model.decision_function(scaler.transform(out[ML_FEATURES])), 4)
    out["ml_daily_anomaly"] = model.predict(scaler.transform(out[ML_FEATURES])) == -1
    out["ml_training_day"] = out.date <= baseline_end
    return out


def detect_events(df: pd.DataFrame, lookup: dict, ml_daily: pd.DataFrame) -> pd.DataFrame:
    """Rules plus user-specific statistical baselines and auxiliary ML signal."""
    failures = (df.log_type == "authentication") & (df.action == "login") & (df.status == "failed")
    downloads = (df.log_type == "file_access") & (df.action == "download")
    failure_counts = rolling_event_counts(df, failures, "30min")
    download_counts = rolling_event_counts(df, downloads, "60min")
    ml_index = ml_daily.set_index(["user", "date"])["ml_daily_anomaly"].to_dict()

    findings = []
    for r in df.itertuples(index=False):
        reasons = []
        flags = []
        score = 0

        def mark(code: str, reason: str, points: int):
            nonlocal score
            flags.append(code)
            reasons.append(reason)
            score += points

        baseline = lookup.get(r.user)
        is_login = r.log_type == "authentication" and r.action == "login"
        outside_hours = r.hour < BUSINESS_START_HOUR or r.hour >= BUSINESS_END_HOUR
        if is_login and outside_hours:
            mark("after_hours_login", f"Login at {r.timestamp:%H:%M}, outside 07:00-19:00", 25)
        if is_login and baseline and r.status == "success":
            login_hour = r.timestamp.hour + r.timestamp.minute / 60
            diff = abs(login_hour - baseline["normal_login_hour_mean"])
            limit = max(2.0, 2.5 * baseline["normal_login_hour_std"])
            if diff > limit:
                mark("login_time_anomaly", f"Login time {diff:.1f}h from user's baseline", 20)
            if r.device not in baseline["device_set"] and r.device not in {"none", "", "nan"}:
                mark("new_device", f"Previously unseen login device: {r.device}", 30)
        if is_login and r.status == "failed" and failure_counts.get(r.event_id, 0) >= 3:
            mark("failed_login_burst", f"{failure_counts[r.event_id]} failed logins in 30 minutes", 30)
        if r.log_type == "file_access" and r.action == "download" and baseline:
            num_downloads = download_counts.get(r.event_id, 0)
            if num_downloads >= baseline["download_burst_threshold"]:
                mark("download_burst", f"{num_downloads} downloads in 60 minutes", 30)
            if outside_hours and any(word in r.resource for word in ("payroll", "source_code", "employee_roster", "budget")):
                mark("after_hours_sensitive_file", f"Sensitive file downloaded after hours: {r.resource}", 15)
        if r.log_type == "privilege_use" and (
            r.action in {"permission_change_attempt", "role_lookup"} or
            (outside_hours and r.action == "admin_tool_open")
        ):
            mark("privilege_risk", f"Unusual privilege activity: {r.action}", 35)
        if r.log_type == "hdr_human_risk":
            risk_actions = {
                "phishing_link_clicked": "Phishing link clicked",
                "credential_submission_detected": "Credential submitted to suspicious site",
                "security_warning_bypassed": "Security warning bypassed",
            }
            if r.action in risk_actions:
                mark("hdr_signal", risk_actions[r.action], 40)
        if r.log_type == "endpoint_activity" and (
            r.action == "archive_create" or
            (r.action == "process_start" and outside_hours and
             any(word in r.resource for word in ("powershell", "cmd.exe", "whoami", "net user")))
        ):
            mark("endpoint_risk", f"Suspicious endpoint activity: {r.action}", 25)

        rule_points = score
        ml_anomaly = bool(ml_index.get((r.user, r.date), False))
        # A user-day ML outlier reinforces supported event-level evidence; alone
        # it never invents an event-level alert.
        if ml_anomaly and rule_points >= 15:
            mark("ml_behavior_outlier", "User-day behavior differs from learned training days", 10)
        score = min(100, score)
        flagged = score >= 25
        findings.append({
            "event_id": r.event_id, "timestamp": r.timestamp, "user": r.user,
            "log_type": r.log_type, "action": r.action, "device": r.device,
            "rule_score": rule_points, "risk_score": score,
            "alert": flagged, "rule_flags": ";".join(flags),
            "explanation": " | ".join(reasons) if reasons else "No suspicious evidence detected",
            "ml_daily_anomaly": ml_anomaly,
        })
    return pd.DataFrame(findings)


def correlate_alerts(alerts: pd.DataFrame, window_hours: int = 24) -> pd.DataFrame:
    """Link flagged events by user/time. Do NOT use incident_id as a shortcut."""
    rows = []
    case_number = 0
    for user, group in alerts.groupby("user", sort=True):
        group = group.sort_values("timestamp")
        buckets = []
        bucket = []
        last = None
        for _, e in group.iterrows():
            if last is not None and e.timestamp - last > pd.Timedelta(hours=window_hours):
                buckets.append(bucket)
                bucket = []
            bucket.append(e)
            last = e.timestamp
        if bucket:
            buckets.append(bucket)
        for events in buckets:
            case_number += 1
            flags = sorted(set(f for e in events for f in str(e.rule_flags).split(";") if f))
            types = sorted(set(e.log_type for e in events))
            high = max(int(e.risk_score) for e in events)
            score = min(100, high + 10 * (len(types) - 1) + 3 * (len(flags) - 1))
            level = "high" if score >= 75 else "medium" if score >= 50 else "low"
            rows.append({
                "case_id": f"CASE-{case_number:04d}", "user": user,
                "first_event": events[0].timestamp, "last_event": events[-1].timestamp,
                "alert_count": len(events), "log_types": ";".join(types),
                "distinct_rule_flags": ";".join(flags),
                "case_risk_score": score, "case_priority": level,
                "event_ids": ";".join(e.event_id for e in events),
                "explanation": f"{len(events)} alerts from {len(types)} log categories: {', '.join(flags)}",
            })
    return pd.DataFrame(rows, columns=[
        "case_id", "user", "first_event", "last_event", "alert_count", "log_types",
        "distinct_rule_flags", "case_risk_score", "case_priority", "event_ids", "explanation",
    ])


def write_validation_report(source: pd.DataFrame, event_results: pd.DataFrame,
                            cases: pd.DataFrame, report_path: Path, baseline_end: str) -> str:
    """Evaluate only after detection. Ground-truth fields are never model inputs."""
    joined = event_results.merge(source[["event_id", "label", "incident_id"]], on="event_id", how="left")
    suspicious = joined.label.astype(str).str.lower().eq("suspicious")
    pred = joined.alert.astype(bool)
    tp = int((pred & suspicious).sum())
    fn = int((~pred & suspicious).sum())
    fp = int((pred & ~suspicious).sum())
    tn = int((~pred & ~suspicious).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    injected = joined.loc[joined.incident_id.astype(str).ne("none") & joined.incident_id.notna()]
    lines = [
        "SYNTHETIC SOC ANOMALY DETECTION - VALIDATION RESULTS",
        f"Baseline ends: {baseline_end} (first seven distinct days; no future incident events used)",
        f"Total events: {len(joined)}", f"Flagged event alerts: {int(pred.sum())}",
        f"Correlated cases: {len(cases)}",
        f"Synthetic event-level confusion matrix: TP={tp}, FP={fp}, FN={fn}, TN={tn}",
        f"Synthetic event-level precision: {precision:.3f}",
        f"Synthetic event-level recall: {recall:.3f}",
        f"Injected incident events flagged: {int(injected.alert.sum())}/{len(injected)}",
        "NOTE: Label and incident_id were used ONLY for validation, not detection or correlation.",
        "NOTE: Synthetic-data results do not establish real-world detection performance.",
        "NOTE: File-volume is estimated from download counts; no byte-count field exists.",
        "NOTE: 'AI' is a demo IsolationForest user-day model, not a trained production SOC system.",
    ]
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Simulated SOC rule + behavior anomaly detection")
    ap.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    ap.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--baseline-days", type=int, default=7)
    args = ap.parse_args()

    source = load_detection_input(args.input)
    train, end_date = split_training_days(source, args.baseline_days)
    baseline_df, baseline_lookup = make_user_baselines(train)
    daily = make_daily_features(source)
    ml_daily = run_ml_daily_anomaly(daily, end_date)
    results = detect_events(source, baseline_lookup, ml_daily)
    alerts = results.loc[results.alert].copy()
    cases = correlate_alerts(alerts)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for filename, data in [
        ("user_baselines.csv", baseline_df),
        ("ml_daily_anomalies.csv", ml_daily),
        ("detection_event_results.csv", results),
        ("detection_alerts.csv", alerts),
        ("correlated_cases.csv", cases),
    ]:
        data.to_csv(args.output_dir / filename, index=False)
        print(f"Saved {filename}: {len(data)} rows")
    report = write_validation_report(source, results, cases, args.output_dir / "detection_test_report.txt", end_date)
    print("\n" + report)


if __name__ == "__main__":
    main()
