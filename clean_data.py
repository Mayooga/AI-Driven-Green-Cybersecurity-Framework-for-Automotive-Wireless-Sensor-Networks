"""
clean_data.py
Step 1 of the pipeline:
- Load all raw hardware-captured CSVs (normal_run1.csv, flood_run1.csv, etc.)
- Sanitize timestamps and packet_size (strip serial noise, coerce to numeric)
- Detect rejected packets from either the receiver's auth_ok field or legacy
  DECRYPT_FAIL text, and mark their sensor value missing.
- Assign target labels from capture filenames, not from receiver decisions.
- Compute causal time-series features per capture session, without using the
  target label to define feature windows.
- Save combined, clean data (with NaNs left in place for missing/failed
  readings -- imputation happens later, per LOSO fold, in train_model.py)
  ready for grouped Leave-One-Session-Out Cross Validation (LOSO-CV).

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

# Raw runs belong in data/ and use names such as normal_run1.csv,
# flood_run1.csv, replay_run1.csv, and tamper_run1.csv.
DATA_DIR = BASE_DIR / "data"


def parse_filename(filepath: Path):
    """
    Parse one capture file using <class>_run<number>.csv.
    The returned class is always canonical (normal/flood/replay/tamper),
    while the full stem remains the session ID. Thus normal_run1 and
    normal_run2 share a class but remain separate capture sessions.

    Also accept the one legacy replay_<timestamp>.csv file currently in data/.
    """
    stem = filepath.stem.lower()
    match = re.fullmatch(r"(normal|flood|flooding|replay|tamper)_run(\d+)", stem)
    if match:
        label = match.group(1)
        if label == "flooding":
            label = "flood"
        return label, stem

    # Preserve the older replay capture until it is replaced by replay_runN.
    if re.fullmatch(r"replay_\d+", stem):
        return "replay", stem

    raise ValueError(
        f"{filepath.name}: expected <normal|flood|replay|tamper>_run<number>.csv"
    )


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
    df.columns = df.columns.astype(str).str.strip()

    # Receiver firmware's current schema differs from the older timestamp,
    # packet_size, value schema. Map its telemetry columns into the common
    # feature pipeline without discarding the receiver's sequence/replay flag.
    aliases = {"t_ms": "timestamp", "len": "packet_size", "current": "value"}
    df = df.rename(columns={k: v for k, v in aliases.items() if k in df.columns})
    if "timestamp" not in df or "value" not in df:
        raise ValueError(f"{filepath}: expected timestamp/value or t_ms/current columns")
    if "packet_size" not in df:
        df["packet_size"] = 0

    # The filename identifies the capture class. Normalize any labels already
    # written by the capture script (e.g. flooding1, replay6, tamper3) to the
    # canonical class name used by the model. Keep the raw value for auditing.
    if "label" in df.columns:
        df["source_label"] = df["label"].astype(str).str.strip()
        source_labels = sorted(set(df["source_label"].dropna()))
        if source_labels and source_labels != [label]:
            print(
                f"[{filepath.name}] normalized source labels {source_labels} "
                f"to class '{label}' from filename"
            )
    df["label"] = label
    df["session"] = session
    # Keep the receiver's replay column as audit data, but never use its
    # decision as the target label. That would make evaluation measure how
    # well the model copies the receiver's own anti-replay decision.

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

    # Current receiver rows carry auth_ok=0 and a numeric zero sensor value
    # on failed authentication. Legacy rows may instead contain DECRYPT_FAIL.
    is_fail_text = df["value"].astype(str).str.contains("DECRYPT_FAIL", case=False, na=False)
    if "auth_ok" in df.columns:
        auth_ok = pd.to_numeric(df["auth_ok"], errors="coerce")
        is_auth_failure = auth_ok.eq(0)
    else:
        is_auth_failure = pd.Series(False, index=df.index)
    df["is_decrypt_fail"] = (is_fail_text | is_auth_failure).astype(int)
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
    Compute causal time-series features per capture session. Grouping by the
    target label would make feature windows depend on ground-truth labels and
    would reset them at the normal-to-attack transition in mixed captures.
    """
    processed_sessions = []

    for session, g in df.groupby("session", sort=False):
        g = g.sort_values("timestamp").copy().reset_index(drop=True)

        # 1. Inter-packet arrival time (ms) & timing variance. The first gap
        # is unknown at inference time, so use zero instead of a whole-session
        # median that would look ahead into later packets.
        g["inter_packet_ms"] = g["timestamp"].diff()
        g["inter_packet_ms"] = g["inter_packet_ms"].fillna(0)

        # Rolling standard deviation of inter-packet arrival time (5-packet window)
        g["inter_packet_std_5"] = g["inter_packet_ms"].rolling(window=5, min_periods=1).std().fillna(0)

        # 2. Packet rate (packets in last 1000ms window)
        times = g["timestamp"].to_numpy()
        rate = np.empty(len(times), dtype=np.int32)
        left = 0
        for right, t in enumerate(times):
            while left <= right and times[left] < t - 1000:
                left += 1
            rate[right] = right - left + 1
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

    if not processed_sessions:
        return df.iloc[0:0].copy()
    return pd.concat(processed_sessions, ignore_index=True)


def main():
    print("=== Cleaning Hardware Telemetry Data from data/ ===")

    if not DATA_DIR.exists():
        raise FileNotFoundError(f"Create the raw capture folder first: {DATA_DIR}")
    csv_files = sorted(DATA_DIR.glob("*.csv"))
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
    print("\n--- Canonical class labels ---")
    print(sorted(clean_df["label"].dropna().unique().tolist()))


if __name__ == "__main__":
    main()
