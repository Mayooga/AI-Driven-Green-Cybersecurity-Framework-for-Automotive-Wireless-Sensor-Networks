"""
clean_data.py
Step 1 of the pipeline:
- Load all raw hardware-captured CSVs (normal_run1.csv, flood_run1.csv, etc.)
- Sanitize timestamps and packet_size (strip serial noise, coerce to numeric)
- Detect decrypt failures from the ACTUAL captured value field, for every
  file, not just files labeled "tamper" -- this avoids manufacturing a
  trivially-learnable constant feature for one class.
- Compute causal time-series features STRICTLY PER-SESSION to eliminate
  cross-session data leakage.
- Save combined, clean data (with NaNs left in place for missing/failed
  readings -- imputation happens later, per LOSO fold, in train_model.py)
  ready for Leave-One-Session-Out Cross Validation (LOSO-CV).

Usage:
    python clean_data.py
Output:
    combined_clean.csv
"""

import re
from pathlib import Path

import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent

# Look in a "data/" subfolder if it exists, otherwise fall back to the
# script's own folder (this is where your CSVs currently sit).
DATA_DIR = BASE_DIR / "data" if (BASE_DIR / "data").exists() else BASE_DIR


def parse_filename(filepath: Path):
    """
    Extract label and session from filename.
    Examples:
        normal_run1.csv -> label='normal', session='run1'
        flood_data.csv  -> label='flood', session='session1'
    """
    stem = filepath.stem.lower()
    # Current captures use names such as replay_1794421908.csv or
    # normal5_1794418865.csv. Keep each file as an independent session.
    for prefix in ("normal", "replay", "flood", "flooding", "tamper"):
        if stem.startswith(prefix):
            label = "flood" if prefix == "flooding" else prefix
            return label, stem
    if "_run" in stem:
        parts = stem.split("_run")
        label = parts[0]
        session = f"run{parts[1]}"
    elif "_data" in stem:
        label = stem.replace("_data", "")
        session = "session1"
    else:
        label = stem
        session = "session1"
    return label, session


def extract_digits(val):
    """Pull the first run of digits out of a value that may contain UART
    noise (e.g. '_FAST_FLASH153'). Returns NaN if no digits are found."""
    if pd.isna(val):
        return np.nan
    m = re.search(r"\d+", str(val))
    return int(m.group()) if m else np.nan


def load_and_sanitize(filepath: Path):
    """
    Load a raw hardware CSV file, parse corrupt timestamps/packet sizes,
    and flag decrypt failures from the ACTUAL value field -- uniformly,
    regardless of what the filename says the label is. This matters: it
    means "is_decrypt_fail" reflects what the hardware really reported,
    not an assumption baked in for one class.
    """
    label, session = parse_filename(filepath)
    df = pd.read_csv(filepath)

    # Receiver firmware's current schema differs from the older timestamp,
    # packet_size, value schema. Map its telemetry columns into the common
    # feature pipeline without discarding the receiver's sequence/replay flag.
    aliases = {"t_ms": "timestamp", "len": "packet_size", "current": "value"}
    df = df.rename(columns={k: v for k, v in aliases.items() if k in df.columns})
    if "timestamp" not in df or "value" not in df:
        raise ValueError(f"{filepath}: expected timestamp/value or t_ms/current columns")
    if "packet_size" not in df:
        df["packet_size"] = 0

    # Standardize label & session columns (filename is treated as ground
    # truth for which experiment this file belongs to).
    df["label"] = label
    df["session"] = session
    # A replay flag is emitted only after the receiver successfully
    # authenticates a packet and finds a duplicate/old sequence number.
    # Use it as the event label in mixed replay recordings.
    if "replay" in df.columns and label == "replay":
        replay_flag = pd.to_numeric(df["replay"], errors="coerce").fillna(0).astype(int)
        df["label"] = np.where(replay_flag == 1, "replay", "normal")

    # --- Clean timestamp (strip UART noise, drop unparsable rows) ---
    df["timestamp"] = df["timestamp"].apply(extract_digits)
    before_count = len(df)
    df = df.dropna(subset=["timestamp"]).reset_index(drop=True)
    df["timestamp"] = df["timestamp"].astype(int)
    dropped_ts = before_count - len(df)

    # --- Clean packet_size (kept as a feature, not dropped) ---
    coerced_pkt = 0
    if "packet_size" in df.columns:
        raw_pkt = df["packet_size"]
        df["packet_size"] = raw_pkt.apply(extract_digits)
        coerced_pkt = int(df["packet_size"].isna().sum())
        # fill any unparsable packet_size with the file's own median so we
        # don't lose rows over a secondary feature
        med_pkt = df["packet_size"].median()
        df["packet_size"] = df["packet_size"].fillna(med_pkt if pd.notna(med_pkt) else 0)
    else:
        df["packet_size"] = np.nan

    # --- Decrypt-failure detection from the real value field, for every file ---
    is_fail_str = df["value"].astype(str).str.contains("DECRYPT_FAIL", case=False, na=False)
    df["is_decrypt_fail"] = is_fail_str.astype(int)
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    # NaNs that appear here are either genuine DECRYPT_FAIL rows, or
    # leftover parse noise. Track them separately so we can report both.
    coerced_val = int(df.loc[df["is_decrypt_fail"] == 0, "value"].isna().sum())
    df.loc[df["is_decrypt_fail"] == 1, "value"] = np.nan

    if dropped_ts or coerced_pkt or coerced_val:
        print(
            f"[{filepath.name}] dropped_bad_timestamp={dropped_ts}, "
            f"coerced_packet_size={coerced_pkt}, "
            f"non_fail_rows_with_unparsable_value={coerced_val}, "
            f"decrypt_fail_rows={int(df['is_decrypt_fail'].sum())}/{len(df)}"
        )

    return df


def engineer_features_per_session(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute time-series rolling features STRICTLY PER (label, session) GROUP.
    This guarantees zero data leakage across different recording sessions.
    Includes inter-packet timing variance and replay timing interaction.
    """
    processed_sessions = []

    for (label, session), g in df.groupby(["label", "session"], sort=False):
        g = g.sort_values("timestamp").copy().reset_index(drop=True)

        # 1. Inter-packet arrival time (ms) & timing variance
        g["inter_packet_ms"] = g["timestamp"].diff()
        median_gap = g["inter_packet_ms"].median()
        g["inter_packet_ms"] = g["inter_packet_ms"].fillna(median_gap if pd.notna(median_gap) else 0)

        # Rolling standard deviation of inter-packet arrival time (5-packet window)
        g["inter_packet_std_5"] = g["inter_packet_ms"].rolling(window=5, min_periods=1).std().fillna(0)

        # 2. Packet rate (packets in last 1000ms window)
        times = g["timestamp"].values
        rate = []
        for i, t in enumerate(times):
            window_start = t - 1000
            count = np.sum((times[: i + 1] >= window_start) & (times[: i + 1] <= t))
            rate.append(count)
        g["packets_per_sec"] = rate

        # 3. Payload repetition features (Replay signature)
        g["is_repeat_value"] = (g["value"] == g["value"].shift(1)).astype(int)
        g.loc[g["is_decrypt_fail"] == 1, "is_repeat_value"] = 0
        g["repeat_rate_5"] = g["is_repeat_value"].rolling(window=5, min_periods=1).mean()

        # 4. Interaction Feature: Combined Repetition + Timing Disruption
        # Distinguishes natural steady readings from injected replay packets
        g["replay_timing_sig"] = g["repeat_rate_5"] * (1.0 + np.log1p(g["inter_packet_std_5"]))

        # 5. Local Z-Score deviation over rolling 10-packet window
        roll_mean = g["value"].rolling(window=10, min_periods=1).mean()
        roll_std = g["value"].rolling(window=10, min_periods=1).std().replace(0, np.nan)
        g["value_zscore"] = ((g["value"] - roll_mean) / roll_std).fillna(0)

        processed_sessions.append(g)

    return pd.concat(processed_sessions, ignore_index=True)


def main():
    print("=== Cleaning Hardware Telemetry Data (Leakage-Free Multi-Session Pipeline) ===")

    csv_files = sorted(list(DATA_DIR.glob("*.csv")))
    # Include root-level captures created by capture.py as well as the
    # documented data/ directory.
    csv_files.extend(sorted(
        p for p in BASE_DIR.glob("*.csv")
        if p.parent == BASE_DIR and p.name.lower().startswith(("normal", "replay", "flood", "tamper"))
    ))
    if not csv_files:
        print(f"Error: No CSV files found in {DATA_DIR}")
        return

    print(f"Found {len(csv_files)} CSV files in {DATA_DIR}:")
    for f in csv_files:
        print(f"  - {f.name}")

    frames = [load_and_sanitize(f) for f in csv_files]
    raw_combined = pd.concat(frames, ignore_index=True)

    clean_df = engineer_features_per_session(raw_combined)

    # NOTE: we deliberately do NOT impute the missing 'value' rows here.
    # Filling them with a global median computed over the whole dataset
    # would leak information from every session (including whichever one
    # ends up as the LOSO test fold) into training. Imputation is done
    # per-fold, using train-only statistics, in train_model.py.

    out_path = BASE_DIR / "combined_clean.csv"
    clean_df.to_csv(out_path, index=False)

    print(f"\nSuccessfully generated {out_path.name} with {len(clean_df)} total rows.")
    print("\n--- Summary by Class & Session ---")
    summary = clean_df.groupby(["label", "session"]).size().unstack(fill_value=0)
    print(summary)

    print("\n--- Missing 'value' rows by class (to be imputed per-fold later) ---")
    print(clean_df.groupby("label")["value"].apply(lambda s: s.isna().sum()))

    print("\n--- Columns Saved ---")
    print(list(clean_df.columns))


if __name__ == "__main__":
    main()
