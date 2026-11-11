"""
live_gateway.py

Real-Time Edge Gateway for IoT Intrusion Detection.

Reads the ESP2 receiver's Serial line, computes all 10 features causally
using a rolling buffer, feeds the feature vector into 'model.joblib',
and writes the live prediction to 'latest_prediction.json'.

Usage:
    python live_gateway.py COM5
    (Replace COM5 with your ESP2 port)
"""

import sys
import json
import time
import re
import math
from collections import deque
from pathlib import Path

import numpy as np
import joblib

try:
    import serial
except ImportError:
    print("ERROR: pyserial not installed. Run: pip install pyserial")
    sys.exit(1)

# ─── CONFIG ──────────────────────────────────────────────────────────────
BASE_DIR        = Path(__file__).resolve().parent
MODEL_PATH      = BASE_DIR / "model.joblib"
ENCODER_PATH    = BASE_DIR / "label_encoder.joblib"
OUTPUT_JSON     = BASE_DIR / "latest_prediction.json"
BAUD_RATE       = 115200
WINDOW_SIZE     = 20
NORMAL_IMPUTE   = 2580.0
# ─────────────────────────────────────────────────────────────────────────

# Feature order MUST match train_model.py exactly
FEATURES = [
    "inter_packet_ms",
    "inter_packet_std_5",
    "packets_per_sec",
    "value",
    "value_zscore",
    "is_repeat_value",
    "repeat_rate_5",
    "replay_timing_sig",
    "is_decrypt_fail",
    "packet_size",
]


def load_model():
    if not MODEL_PATH.exists() or not ENCODER_PATH.exists():
        print(f"ERROR: {MODEL_PATH.name} or {ENCODER_PATH.name} missing. Run train_model.py first.")
        sys.exit(1)
    clf = joblib.load(MODEL_PATH)
    le = joblib.load(ENCODER_PATH)
    print(f"Loaded trained ML model: {MODEL_PATH.name}")
    return clf, le


class CausalFeatureBuffer:
    """
    Maintains a rolling window of recent packets and computes all features
    causally (strictly looking at past packets, no future lookahead).
    """
    def __init__(self, window: int = WINDOW_SIZE, impute_value: float = NORMAL_IMPUTE):
        self.timestamps       = deque(maxlen=window)
        self.values           = deque(maxlen=window)
        self.inter_packet_buf = deque(maxlen=window)
        self.repeat_buf       = deque(maxlen=5)
        self.impute_value     = impute_value

    def push(self, timestamp: int, packet_size: float, raw_value: str) -> dict:
        # 1. is_decrypt_fail
        is_fail = 1 if "DECRYPT_FAIL" in str(raw_value).upper() else 0
        if is_fail:
            value = np.nan
        else:
            try:
                value = float(raw_value)
            except ValueError:
                value = np.nan

        # 2. inter_packet_ms
        if len(self.timestamps) > 0:
            inter_ms = float(timestamp - self.timestamps[-1])
        else:
            inter_ms = 0.0

        self.timestamps.append(timestamp)
        self.inter_packet_buf.append(inter_ms)

        # 3. inter_packet_std_5
        if len(self.inter_packet_buf) >= 2:
            inter_packet_std_5 = float(np.std(list(self.inter_packet_buf)[-5:]))
        else:
            inter_packet_std_5 = 0.0

        # 4. packets_per_sec (within last 1000ms)
        ts_list = list(self.timestamps)
        packets_per_sec = sum(1 for t in ts_list if timestamp - t <= 1000)

        # 5. is_repeat_value
        prev_val = self.values[-1] if len(self.values) > 0 else np.nan
        if is_fail:
            is_repeat = 0
        elif not np.isnan(value) and not np.isnan(prev_val) and value == prev_val:
            is_repeat = 1
        else:
            is_repeat = 0

        self.values.append(value if not np.isnan(value) else np.nan)
        self.repeat_buf.append(is_repeat)

        # 6. repeat_rate_5
        repeat_rate_5 = float(np.mean(list(self.repeat_buf)))

        # 7. replay_timing_sig
        replay_timing_sig = repeat_rate_5 * (1.0 + math.log1p(inter_packet_std_5))

        # 8. value_zscore
        valid_vals = [v for v in list(self.values) if not np.isnan(v)]
        if len(valid_vals) >= 2:
            roll_mean = float(np.mean(valid_vals[-10:]))
            roll_std  = float(np.std(valid_vals[-10:]))
            imputed   = value if not np.isnan(value) else roll_mean
            value_zscore = (imputed - roll_mean) / roll_std if roll_std > 0 else 0.0
        else:
            value_zscore = 0.0

        # 9. Final numeric value for model input
        feat_value = value if not np.isnan(value) else (
            float(np.mean(valid_vals)) if valid_vals else self.impute_value
        )

        return {
            "inter_packet_ms"   : inter_ms,
            "inter_packet_std_5": inter_packet_std_5,
            "packets_per_sec"   : packets_per_sec,
            "value"             : feat_value,
            "value_zscore"      : value_zscore,
            "is_repeat_value"   : is_repeat,
            "repeat_rate_5"     : repeat_rate_5,
            "replay_timing_sig" : replay_timing_sig,
            "is_decrypt_fail"   : is_fail,
            "packet_size"       : packet_size,
        }


def parse_serial_line(line: str):
    parts = line.strip().split(",")
    if len(parts) != 3:
        return None
    try:
        timestamp = int(re.search(r"\d+", parts[0]).group())
        pkt_size  = float(re.search(r"\d+", parts[1]).group())
        raw_val   = parts[2].strip()
        return timestamp, pkt_size, raw_val
    except (AttributeError, ValueError):
        return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python live_gateway.py <PORT>")
        print("Example: python live_gateway.py COM5")
        sys.exit(1)

    port = sys.argv[1]
    clf, le = load_model()
    buffer = CausalFeatureBuffer()

    print(f"\nOpening {port} at {BAUD_RATE} baud...")
    ser = serial.Serial(port, BAUD_RATE, timeout=1)
    print("Listening to ESP2 stream and running ML predictions...")
    print(f"Writing live results to: {OUTPUT_JSON.name}\n")

    packet_count = 0
    history = []

    try:
        while True:
            raw_line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not raw_line:
                continue

            parsed = parse_serial_line(raw_line)
            if parsed is None:
                continue

            timestamp, pkt_size, raw_value = parsed
            feats = buffer.push(timestamp, pkt_size, raw_value)

            # Build feature array in exact order
            X = np.array([[feats[f] for f in FEATURES]])

            # ML Inference
            pred_idx   = clf.predict(X)[0]
            pred_label = le.inverse_transform([pred_idx])[0]
            proba      = clf.predict_proba(X)[0]
            confidence = float(proba[pred_idx]) * 100.0

            packet_count += 1

            prob_dict = {
                cls_name: round(float(p) * 100.0, 1)
                for cls_name, p in zip(le.classes_, proba)
            }

            record = {
                "packet_count" : packet_count,
                "timestamp_ms" : timestamp,
                "raw_value"    : raw_value,
                "predicted"    : pred_label,
                "confidence"   : round(confidence, 1),
                "is_attack"    : (pred_label != "normal"),
                "probabilities": prob_dict,
                "features"     : {k: round(v, 3) for k, v in feats.items()},
                "updated_at"   : time.strftime("%H:%M:%S"),
            }

            # Maintain recent 30 history entries for dashboard graphs
            history.append({
                "time": record["updated_at"],
                "predicted": pred_label,
                "inter_ms": feats["inter_packet_ms"],
                "pps": feats["packets_per_sec"],
                "repeat_rate": feats["repeat_rate_5"],
            })
            if len(history) > 30:
                history.pop(0)

            # Atomically write JSON for dashboard
            output_payload = {
                "latest": record,
                "history": history
            }
            with open(OUTPUT_JSON, "w") as f:
                json.dump(output_payload, f)

            status = "⚠ ATTACK" if record["is_attack"] else "✓ NORMAL"
            print(f"[{record['updated_at']}] #{packet_count:04d} | {status:10s} | "
                  f"Class: {pred_label:<8} ({confidence:5.1f}%) | Val: {raw_value}")

    except KeyboardInterrupt:
        print("\nGateway stopped.")
    finally:
        ser.close()


if __name__ == "__main__":
    main()