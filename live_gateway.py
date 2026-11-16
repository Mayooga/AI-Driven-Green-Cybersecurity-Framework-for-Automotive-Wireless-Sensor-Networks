"""
live_gateway.py

Real-Time Edge Gateway for IoT Intrusion Detection.

Reads the ESP2 receiver's Serial line, computes the trained features causally
using a rolling buffer, feeds the feature vector into 'model.joblib',
and writes the live prediction to 'latest_prediction.json'.

Usage:
    python live_gateway.py COM5
    (Replace COM5 with your ESP2 port)
"""

import sys
import json
import time
import math
from collections import deque
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from model_features import FEATURES

try:
    import serial
except ImportError:
    print("ERROR: pyserial not installed. Run: pip install pyserial")
    sys.exit(1)

# ─── CONFIG ──────────────────────────────────────────────────────────────
BASE_DIR        = Path(__file__).resolve().parent
MODEL_PATH      = BASE_DIR / "model.joblib"
ENCODER_PATH    = BASE_DIR / "label_encoder.joblib"
MEDIANS_PATH    = BASE_DIR / "feature_medians.joblib"
OUTPUT_JSON     = BASE_DIR / "latest_prediction.json"
BAUD_RATE       = 115200

# Energy-aware mode: these values are a lightweight prototype estimate used to
# explain the framework's green design. They are not hardware-calibrated power
# measurements and should be treated as an operational estimate for the gateway.
BASE_TX_UJ      = 40.0
BYTE_TX_UJ      = 0.25
ML_INFER_UJ     = 12.0
DEFENSE_UJ      = 18.0
SLEEP_LOW_POWER = 0.55
THREAT_BUDGET_J = 12.0
# ─────────────────────────────────────────────────────────────────────────

def load_model():
    required_paths = (MODEL_PATH, ENCODER_PATH, MEDIANS_PATH)
    missing = [path.name for path in required_paths if not path.exists()]
    if missing:
        print(f"ERROR: Missing {', '.join(missing)}. Run train_model.py first.")
        sys.exit(1)
    clf = joblib.load(MODEL_PATH)
    le = joblib.load(ENCODER_PATH)
    medians = joblib.load(MEDIANS_PATH)
    model_features = getattr(clf, "feature_names_in_", None)
    if model_features is not None and list(model_features) != FEATURES:
        raise ValueError(
            "The trained model feature columns do not match model_features.py. "
            "Run train_model.py to rebuild the model artifacts."
        )
    feature_count = getattr(clf, "n_features_in_", len(FEATURES))
    if feature_count != len(FEATURES) or list(medians.index) != FEATURES:
        raise ValueError(
            "The trained model and feature medians do not match model_features.py. "
            "Run train_model.py to rebuild the model artifacts."
        )
    print(f"Loaded trained ML model: {MODEL_PATH.name}")
    return clf, le, medians


class CausalFeatureBuffer:
    """Compute the same causal features used by clean_data.py."""

    def __init__(self):
        self.timestamps = deque()
        self.values = deque(maxlen=10)
        self.inter_packet_buf = deque(maxlen=5)
        self.repeat_buf       = deque(maxlen=5)

    def push(self, timestamp: int, packet_size: float, raw_value: float | None) -> dict:
        value = float(raw_value) if raw_value is not None else np.nan
        inter_ms = float(timestamp - self.timestamps[-1]) if self.timestamps else 0.0
        self.timestamps.append(timestamp)
        self.inter_packet_buf.append(inter_ms)

        while self.timestamps and timestamp - self.timestamps[0] > 1000:
            self.timestamps.popleft()
        packets_per_sec = len(self.timestamps)
        inter_packet_std_5 = (
            float(np.std(self.inter_packet_buf, ddof=1))
            if len(self.inter_packet_buf) > 1 else 0.0
        )

        prev_val = self.values[-1] if len(self.values) > 0 else np.nan
        is_repeat = int(not np.isnan(value) and not np.isnan(prev_val) and value == prev_val)
        self.values.append(value)
        self.repeat_buf.append(is_repeat)
        repeat_rate_5 = float(np.mean(list(self.repeat_buf)))
        replay_timing_sig = repeat_rate_5 * (1.0 + math.log1p(inter_packet_std_5))

        valid_vals = [v for v in self.values if not np.isnan(v)]
        if not np.isnan(value) and len(valid_vals) > 1:
            roll_mean = float(np.mean(valid_vals))
            roll_std = float(np.std(valid_vals, ddof=1))
            value_zscore = (value - roll_mean) / roll_std if roll_std > 0 else 0.0
        else:
            value_zscore = 0.0

        return {
            "inter_packet_ms"   : inter_ms,
            "inter_packet_std_5": inter_packet_std_5,
            "packets_per_sec"   : packets_per_sec,
            "value"             : value,
            "value_zscore"      : value_zscore,
            "is_repeat_value"   : is_repeat,
            "repeat_rate_5"     : repeat_rate_5,
            "replay_timing_sig" : replay_timing_sig,
            "packet_size"       : packet_size,
        }


def parse_serial_line(line: str) -> tuple[int, float, float | None] | None:
    parts = line.strip().split(",")
    if len(parts) == 3:
        try:
            timestamp = int(parts[0])
            packet_size = float(parts[1])
            raw_value = None if "DECRYPT_FAIL" in parts[2].upper() else float(parts[2])
            return timestamp, packet_size, raw_value
        except ValueError:
            return None
    if len(parts) not in (11, 12):
        return None

    try:
        timestamp = int(parts[0])
        auth_ok = int(parts[2])
        packet_size = float(parts[3])
        raw_value = float(parts[6]) if auth_ok == 1 else None
        if auth_ok not in (0, 1):
            return None
        return timestamp, packet_size, raw_value
    except ValueError:
        return None


class EnergyAwareSecurityState:
    """Prototype energy model for a low-power, adaptive security policy."""

    def __init__(self):
        self.total_energy_j = 0.0
        self.packet_count = 0
        self.energy_budget_j = THREAT_BUDGET_J

    def estimate_packet_energy(self, packet_size: float, pred_label: str, is_attack: bool, confidence: float):
        # Transmission cost scales with packet size; defensive modes increase the
        # security cost slightly, while normal traffic keeps the footprint lower.
        energy_uj = BASE_TX_UJ + (packet_size * BYTE_TX_UJ)
        energy_uj += ML_INFER_UJ
        if is_attack or pred_label != "normal":
            energy_uj += DEFENSE_UJ + (confidence * 6.0)
        else:
            energy_uj += 3.0

        # If the node is under low-power budget, reduce extra monitoring cost to
        # stay closer to the sustainability objective.
        if self.total_energy_j >= self.energy_budget_j * 0.75:
            energy_uj *= SLEEP_LOW_POWER

        return energy_uj / 1_000_000.0  # Joules

    def record(self, packet_size: float, pred_label: str, is_attack: bool, confidence: float):
        self.packet_count += 1
        energy_j = self.estimate_packet_energy(packet_size, pred_label, is_attack, confidence)
        self.total_energy_j += energy_j
        avg = self.total_energy_j / max(self.packet_count, 1)

        return {
            "total_energy_j": round(self.total_energy_j, 6),
            "energy_per_packet_j": round(avg, 6),
            "security_mode": "adaptive-defense" if is_attack or pred_label != "normal" else "low-power-monitoring",
            "energy_budget_remaining_pct": round(max(0.0, 100.0 * (1.0 - (self.total_energy_j / self.energy_budget_j))), 2),
        }


def main():
    if len(sys.argv) < 2:
        print("Usage: python live_gateway.py <PORT>")
        print("Example: python live_gateway.py COM5")
        sys.exit(1)

    port = sys.argv[1]
    clf, le, medians = load_model()
    buffer = CausalFeatureBuffer()
    energy_state = EnergyAwareSecurityState()

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

            timestamp, packet_size, raw_value = parsed
            feats = buffer.push(timestamp, packet_size, raw_value)

            X = pd.DataFrame([feats], columns=FEATURES).fillna(medians)

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

            energy_profile = energy_state.record(packet_size, pred_label, pred_label != "normal", float(confidence) / 100.0)

            record = {
                "packet_count" : packet_count,
                "timestamp_ms" : timestamp,
                "raw_value"    : raw_value,
                "predicted"    : pred_label,
                "confidence"   : round(confidence, 1),
                "is_attack"    : (pred_label != "normal"),
                "probabilities": prob_dict,
                "features"     : {
                    k: round(float(v), 3) if np.isfinite(v) else None
                    for k, v in feats.items()
                },
                "energy_profile": energy_profile,
                "updated_at"   : time.strftime("%H:%M:%S"),
            }

            # Maintain recent 30 history entries for dashboard graphs
            history.append({
                "packet_count": packet_count,
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
