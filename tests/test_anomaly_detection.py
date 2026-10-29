"""Regression tests for the capstone's provided synthetic dataset.
Run from repository root: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from anomaly_detection import (  # noqa: E402
    correlate_alerts, detect_events, load_detection_input, make_daily_features,
    make_user_baselines, run_ml_daily_anomaly, split_training_days,
)


class DetectionPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_detection_input(ROOT / "outputs" / "cleaned_all_logs.csv")
        cls.training, cls.last_training = split_training_days(cls.events, 7)
        cls.baseline_df, cls.baselines = make_user_baselines(cls.training)
        cls.ml_daily = run_ml_daily_anomaly(make_daily_features(cls.events), cls.last_training)
        cls.results = detect_events(cls.events, cls.baselines, cls.ml_daily)
        cls.alerts = cls.results.loc[cls.results.alert].copy()
        cls.cases = correlate_alerts(cls.alerts)

    def test_dataset_loaded(self):
        self.assertEqual(len(self.events), 453)
        self.assertEqual(self.events.event_id.nunique(), 453)

    def test_training_uses_prior_days_only(self):
        self.assertEqual(self.last_training, "2026-09-22")
        self.assertNotIn("unknown-device", self.baselines["m.chen"]["device_set"])
        self.assertEqual(len(self.baseline_df), 10)

    def test_after_hours_and_new_device(self):
        login = self.results.set_index("event_id").loc["AUTH-0165"]
        self.assertIn("after_hours_login", login.rule_flags)
        self.assertIn("new_device", login.rule_flags)
        self.assertIn("login_time_anomaly", login.rule_flags)
        self.assertTrue(login.alert)

    def test_failed_logins(self):
        failed = self.results.set_index("event_id").loc["AUTH-0164"]
        self.assertIn("failed_login_burst", failed.rule_flags)

    def test_file_volume_and_sensitive_files(self):
        downloads = self.results.loc[self.results.event_id.str.startswith("FILE-016")]
        self.assertTrue(downloads.rule_flags.str.contains("download_burst").any())
        self.assertTrue(downloads.rule_flags.str.contains("after_hours_sensitive_file").any())

    def test_hdr_and_privilege_and_endpoint(self):
        m = self.results.set_index("event_id")
        self.assertIn("hdr_signal", m.loc["HDR-0013"].rule_flags)
        self.assertIn("privilege_risk", m.loc["PRIV-0016"].rule_flags)
        self.assertIn("endpoint_risk", m.loc["ENDPOINT-0082"].rule_flags)

    def test_ml_flags_injected_behavior(self):
        incident_day = self.ml_daily.loc[(self.ml_daily.user == "m.chen") &
                                         (self.ml_daily.date == "2026-09-24")]
        self.assertTrue(bool(incident_day.iloc[0].ml_daily_anomaly))

    def test_correlation_and_risk_score(self):
        self.assertEqual(len(self.cases), 1)
        case = self.cases.iloc[0]
        self.assertEqual(case.user, "m.chen")
        self.assertEqual(case.alert_count, 26)
        self.assertEqual(len(case.log_types.split(";")), 5)
        self.assertEqual(case.case_priority, "high")
        self.assertTrue(self.results.risk_score.between(0, 100).all())

    def test_ground_truth_fields_do_not_drive_decisions(self):
        poisoned = self.events.copy()
        for col in ["label", "risk_signal", "severity", "incident_id", "details"]:
            if col in poisoned:
                poisoned[col] = "altered-value-for-leakage-test"
        altered = detect_events(poisoned, self.baselines, self.ml_daily)
        self.assertEqual(self.results.risk_score.tolist(), altered.risk_score.tolist())
        self.assertEqual(self.results.rule_flags.tolist(), altered.rule_flags.tolist())
        self.assertEqual(self.results.alert.tolist(), altered.alert.tolist())

    def test_injected_incident_captured(self):
        eval_data = self.results.merge(self.events[["event_id", "incident_id"]], on="event_id")
        known = eval_data.loc[eval_data.incident_id == "INC-001"]
        self.assertEqual(len(known), 26)
        self.assertTrue(known.alert.all())


if __name__ == "__main__":
    unittest.main()
