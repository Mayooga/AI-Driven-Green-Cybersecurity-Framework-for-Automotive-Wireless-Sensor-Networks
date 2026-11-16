"""Summarize isolated green duty-cycle trials from green_data/runs.csv."""

from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
SUMMARY = BASE_DIR / "green_data" / "runs.csv"


def main():
    if not SUMMARY.exists():
        raise SystemExit("No green_data/runs.csv found. Run green_capture.py for each trial first.")
    df = pd.read_csv(SUMMARY)
    if df.empty:
        raise SystemExit("runs.csv is empty")

    cols = ["sleep_time_pct", "receiver_records_per_s", "authenticated_records", "rejected_records", "replay_records"]
    summary = df.groupby("mode")[cols].agg(["mean", "std", "count"])
    print("Averages across captured trials (std is run-to-run variation):")
    print(summary.round(2).to_string())
    print("\nPer-run details:")
    print(df[["mode", "run", "actual_duration_s", "sender_packets_reported", "sender_awake_ms", "sender_sleep_ms", "sleep_time_pct", "receiver_records", "authenticated_records"]].to_string(index=False))
    print("\nInterpretation: sleep_time_pct is a duty-cycle proxy, not measured energy.")
    print("Compare modes only when run durations and conditions are similar. Investigate any large packet-rate or authentication differences.")


if __name__ == "__main__":
    main()
