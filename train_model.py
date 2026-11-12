"""
train_model.py
Step 2 of the pipeline:
- Load combined_clean.csv
- Hold out complete sessions for normal/flood/tamper and unique replay
  payload identities for replay to avoid duplicate replay packets crossing folds
- Impute any missing values (decrypt-fail rows) using TRAIN-FOLD-ONLY
  statistics, so no information about the held-out session leaks in
- Train and evaluate a Random Forest multiclass attack classifier
- Measure inference latency per sample
- Save final trained model (model.joblib), encoder, confusion matrix, and feature importances

Usage:
    python train_model.py
"""

import hashlib
import re
import time
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay, f1_score
import joblib

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "combined_clean.csv"
CANONICAL_CLASSES = {"normal", "flood", "replay", "tamper"}

FEATURES = [
    "inter_packet_ms",
    "inter_packet_std_5",
    "packets_per_sec",
    "value",
    "value_zscore",
    "is_repeat_value",
    "repeat_rate_5",
    "replay_timing_sig",
    "packet_size",
]


def impute_train_only(X_train: pd.DataFrame, X_test: pd.DataFrame):
    """
    Fill any remaining NaNs (e.g. 'value' on decrypt-fail rows) using
    medians computed from the TRAINING fold only, then apply the same
    medians to the test fold. This keeps the held-out session's own
    values from influencing what gets imputed in training -- the earlier
    version filled a global median in clean_data.py, which technically
    leaked test-fold information into the "leakage-free" pipeline.
    """
    train_medians = X_train.median(numeric_only=True).fillna(0)
    X_train_filled = X_train.fillna(train_medians)
    X_test_filled = X_test.fillna(train_medians)
    return X_train_filled, X_test_filled


def canonicalize_label(value):
    """Accept canonical class names and legacy labels such as flooding2."""
    label = str(value).strip().lower()
    match = re.fullmatch(r"(normal|flood|flooding|replay|tamper)(?:_?run)?\d*", label)
    if not match:
        raise ValueError(
            f"Unknown class label {value!r}. Expected normal, flood, replay, or tamper."
        )
    name = match.group(1)
    return "flood" if name in {"flood", "flooding"} else name


def build_evaluation_groups(df: pd.DataFrame) -> pd.Series:
    """Hold normal/flood/tamper out by session and replay out by payload.

    The replay CSVs contain the same eight decrypted payloads in every file.
    Grouping those rows by payload identity prevents copies of a replay packet
    from appearing in both sides of a fold. This is a packet-disjoint check,
    not evidence of generalization to independently collected attacks.
    """
    groups = "session:" + df["session"].astype(str)
    replay_mask = df["label"].eq("replay")
    if replay_mask.any():
        payload_columns = ["seq", "value", "temp", "hum", "press", "pir"]
        missing = [column for column in payload_columns if column not in df.columns]
        if missing:
            raise ValueError(
                "Replay payload-disjoint evaluation requires these columns in "
                f"combined_clean.csv: {', '.join(missing)}. Run clean_data.py again."
            )

        def stable_value(value):
            if pd.isna(value):
                return "<NA>"
            try:
                return format(float(value), ".10g")
            except (TypeError, ValueError):
                return str(value).strip()

        payload_frame = df.loc[replay_mask, payload_columns].copy()
        for column in payload_columns:
            payload_frame[column] = payload_frame[column].map(stable_value)
        signatures = payload_frame.astype(str).agg("|".join, axis=1)
        payload_groups = signatures.map(
            lambda signature: "replay-payload:" + hashlib.sha256(
                signature.encode("utf-8")
            ).hexdigest()[:12]
        )
        groups.loc[replay_mask] = payload_groups
    return groups


def run_grouped_cross_validation(df: pd.DataFrame, le: LabelEncoder):
    """
    Hold out each normal/flood/tamper capture and each unique replay payload
    once. The latter avoids direct replay-packet duplicates across folds.
    """
    groups = build_evaluation_groups(df)
    unique_groups = sorted(groups.unique())
    if len(unique_groups) < 2:
        raise ValueError("Grouped cross-validation needs at least two evaluation groups.")

    class_group_support = pd.DataFrame({"label": df["label"], "group": groups}).groupby("label")["group"].nunique()
    print(f"\n=======================================================")
    print(" GROUPED HELD-OUT EVALUATION")
    print(f" Evaluation groups detected: {len(unique_groups)}")
    print(" Evaluation groups per class:")
    for label, count in class_group_support.items():
        print(f"   {label}: {count}")
        if count < 2:
            print(f"   WARNING: {label} has fewer than two groups; held-out generalization cannot be measured.")
    print(" Normal/flood/tamper are grouped by capture session; replay is grouped by payload identity.")
    print(" Replay folds are packet-disjoint, but replay rows still come from the same five recordings.")
    print(f"=======================================================\n")

    group_f1_scores = []
    all_y_true = []
    all_y_pred_rf = []
    all_class_ids = np.arange(len(le.classes_))

    logo = LeaveOneGroupOut()
    for fold_idx, (train_idx, test_idx) in enumerate(logo.split(df, groups=groups), 1):
        train_df = df.iloc[train_idx]
        test_df = df.iloc[test_idx]
        test_group = str(groups.iloc[test_idx[0]])

        X_train_raw = train_df[FEATURES]
        y_train = le.transform(train_df["label"])

        X_test_raw = test_df[FEATURES]
        y_test = le.transform(test_df["label"])

        # Impute missing values using TRAIN-fold-only statistics
        X_train, X_test = impute_train_only(X_train_raw, X_test_raw)

        # 1. Random Forest Model
        clf_rf = RandomForestClassifier(
            n_estimators=200, max_depth=8, class_weight="balanced", random_state=42
        )
        clf_rf.fit(X_train, y_train)
        pred_rf = clf_rf.predict(X_test)
        # A held-out capture may contain only one class. Score the classes
        # represented in that session, instead of assigning zero scores to
        # unrelated classes that have no test examples in this fold.
        present_test_classes = np.unique(y_test)
        session_f1 = f1_score(
            y_test, pred_rf, labels=present_test_classes,
            average="macro", zero_division=0
        )
        group_f1_scores.append(session_f1)

        print(f"--- Fold {fold_idx} (Held-out group: {test_group}) ---")
        print(f"  Train samples: {len(train_df)} | Test samples: {len(test_df)}")
        print(f"  Held-out group F1          : {session_f1:.4f}")
        absent_train = sorted(set(le.classes_) - set(train_df["label"].unique()))
        if absent_train:
            print(f"  WARNING: training fold has no examples of {absent_train}; these classes cannot be predicted in this fold.")
        print()

        all_y_true.extend(y_test)
        all_y_pred_rf.extend(pred_rf)

    mean_rf = np.mean(group_f1_scores)
    std_rf = np.std(group_f1_scores)

    print("=======================================================")
    print(" RANDOM FOREST GROUPED EVALUATION SUMMARY")
    print("=======================================================")
    print(f" Mean held-out group F1: {mean_rf:.4f} \u00b1 {std_rf:.4f}")
    pooled_accuracy = accuracy_score(all_y_true, all_y_pred_rf)
    print(f" Pooled held-out-group Accuracy: {pooled_accuracy:.6f}")
    pooled_macro_f1 = f1_score(
        all_y_true, all_y_pred_rf, labels=all_class_ids,
        average="macro", zero_division=0
    )
    print(f" Pooled held-out-group Macro-F1: {pooled_macro_f1:.4f}\n")

    print("=== Aggregated Classification Report (Random Forest) ===")
    print(classification_report(
        all_y_true, all_y_pred_rf, labels=all_class_ids,
        target_names=le.classes_, zero_division=0, digits=6
    ))

    return all_y_true, all_y_pred_rf


def measure_latency(clf, X_sample):
    """
    Measure inference latency per prediction (microseconds per sample).
    NOTE: this measures inference on the machine running this script
    (your PC / gateway), not on the ESP32 itself. Report it in the paper
    as gateway-side inference latency.
    """
    for _ in range(50):
        clf.predict(X_sample.iloc[:1])

    t0 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        clf.predict(X_sample.iloc[:1])
    t1 = time.perf_counter()

    avg_ms = ((t1 - t0) / n_runs) * 1000.0
    avg_us = avg_ms * 1000.0
    return avg_ms, avg_us


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"{DATA_PATH.name} not found. Run clean_data.py first to generate it."
        )
    df = pd.read_csv(DATA_PATH)
    required = set(FEATURES) | {"label", "session"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(
            f"{DATA_PATH.name} is missing required columns: {', '.join(missing)}. "
            "Run clean_data.py to regenerate the cleaned dataset."
        )

    # source_label is retained by clean_data.py for auditing only. Training
    # always uses the canonical label column, never raw capture labels.
    df["label"] = df["label"].map(canonicalize_label)
    unexpected = sorted(set(df["label"].unique()) - CANONICAL_CLASSES)
    if unexpected:
        raise ValueError(f"Unexpected labels after normalization: {unexpected}")
    df["session"] = df["session"].astype(str)
    for feature in FEATURES:
        df[feature] = pd.to_numeric(df[feature], errors="coerce")
    df[FEATURES] = df[FEATURES].replace([np.inf, -np.inf], np.nan)

    print(f"Loaded combined_clean.csv: {len(df)} rows across {df['session'].nunique()} sessions.")
    print(f"Canonical classes: {sorted(df['label'].unique().tolist())}")

    le = LabelEncoder()
    df["label_encoded"] = le.fit_transform(df["label"])
    y = df["label_encoded"]

    all_y_true, all_y_pred_rf = run_grouped_cross_validation(df, le)

    # Train final Random Forest on ALL sessions (for deployment).
    # Impute with the full-dataset median here -- this is fine because
    # this final model is not being evaluated on held-out data, it's the
    # artifact you ship.
    full_medians = df[FEATURES].median(numeric_only=True).fillna(0)
    X_full = df[FEATURES].fillna(full_medians)

    print("Training final Random Forest model on all sessions...")
    clf_final = RandomForestClassifier(
        n_estimators=200, max_depth=8, class_weight="balanced", random_state=42
    )
    clf_final.fit(X_full, y)

    latency_ms, latency_us = measure_latency(clf_final, X_full)
    print(f"\n--- Gateway-Side Inference Latency (host machine, not on-chip) ---")
    print(f" Single Prediction Latency: {latency_us:.2f} \u00b5s ({latency_ms:.4f} ms)")
    print(f" Max Throughput Potential : {int(1000.0 / latency_ms):,} predictions/sec")

    class_ids = np.arange(len(le.classes_))
    cm = confusion_matrix(all_y_true, all_y_pred_rf, labels=class_ids)

    disp = ConfusionMatrixDisplay(cm, display_labels=le.classes_)
    disp.plot(cmap="Blues")
    plt.title("Grouped Held-Out Confusion Matrix (Random Forest)")
    plt.tight_layout()
    plt.savefig(BASE_DIR / "confusion_matrix.png", dpi=150)
    plt.close()

    importances = pd.Series(clf_final.feature_importances_, index=FEATURES).sort_values()
    plt.figure(figsize=(7, 4))
    importances.plot(kind="barh", color="#2b5c8f")
    plt.title("Feature Importance (Random Forest)")
    plt.xlabel("Gini Importance")
    plt.tight_layout()
    plt.savefig(BASE_DIR / "feature_importance.png", dpi=150)
    plt.close()

    joblib.dump(clf_final, BASE_DIR / "model.joblib")
    joblib.dump(le, BASE_DIR / "label_encoder.joblib")
    joblib.dump(full_medians, BASE_DIR / "feature_medians.joblib")

    print("\nSaved model artifacts:")
    print("  - model.joblib")
    print("  - label_encoder.joblib")
    print("  - feature_medians.joblib (use these same medians before inference)")
    print("  - confusion_matrix.png")
    print("  - feature_importance.png")


if __name__ == "__main__":
    main()
