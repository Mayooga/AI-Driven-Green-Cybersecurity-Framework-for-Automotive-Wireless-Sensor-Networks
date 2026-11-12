"""
train_model.py
Step 2 of the pipeline:
- Load combined_clean.csv
- Perform grouped Leave-One-Session-Out Cross Validation (LOSO-CV), holding
  out one complete capture file per fold to avoid packet-level leakage
- Impute any missing values (decrypt-fail rows) using TRAIN-FOLD-ONLY
  statistics, so no information about the held-out session leaks in
- Train and evaluate a Random Forest multiclass attack classifier
- Measure inference latency per sample
- Save final trained model (model.joblib), encoder, confusion matrix, and feature importances

Usage:
    python train_model.py
"""

import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay, f1_score
import joblib

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


def run_loso_cross_validation(df: pd.DataFrame, le: LabelEncoder):
    """
    Hold out each complete capture session once. Rows from one capture are
    highly correlated, so packet-level Leave-One-Out would leak nearly
    identical observations between train and test.
    """
    groups = df["session"].astype(str)
    unique_sessions = sorted(groups.unique())
    if len(unique_sessions) < 2:
        raise ValueError("LOSO-CV needs at least two independent capture sessions.")

    session_support = df.groupby("label")["session"].nunique()
    print(f"\n=======================================================")
    print(f" GROUPED LEAVE-ONE-SESSION-OUT CROSS-VALIDATION (LOSO-CV)")
    print(f" Unique sessions detected: {unique_sessions}")
    print(" Sessions per class:")
    for label, count in session_support.items():
        print(f"   {label}: {count}")
        if count < 2:
            print(f"   WARNING: {label} appears in only one session; held-out-session generalization for this class cannot be measured.")
    print(f"=======================================================\n")

    rf_f1_scores = []
    all_y_true = []
    all_y_pred_rf = []
    all_class_ids = np.arange(len(le.classes_))

    logo = LeaveOneGroupOut()
    for fold_idx, (train_idx, test_idx) in enumerate(logo.split(df, groups=groups), 1):
        train_df = df.iloc[train_idx]
        test_df = df.iloc[test_idx]
        test_session = unique_sessions[fold_idx - 1]

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
        macro_f1_rf = f1_score(
            y_test, pred_rf, labels=all_class_ids, average="macro", zero_division=0
        )
        rf_f1_scores.append(macro_f1_rf)

        print(f"--- Fold {fold_idx} (Held-out Test Session: {test_session}) ---")
        print(f"  Train samples: {len(train_df)} | Test samples: {len(test_df)}")
        print(f"  Random Forest Macro-F1     : {macro_f1_rf:.4f}")
        absent_train = sorted(set(le.classes_) - set(train_df["label"].unique()))
        if absent_train:
            print(f"  WARNING: training fold has no examples of {absent_train}; these classes cannot be predicted in this fold.")
        print()

        all_y_true.extend(y_test)
        all_y_pred_rf.extend(pred_rf)

    mean_rf = np.mean(rf_f1_scores)
    std_rf = np.std(rf_f1_scores)

    print("=======================================================")
    print(" RANDOM FOREST LOSO-CV SUMMARY")
    print("=======================================================")
    print(f" Mean session Macro-F1: {mean_rf:.4f} \u00b1 {std_rf:.4f}\n")

    print("=== Aggregated Classification Report (Random Forest) ===")
    print(classification_report(
        all_y_true, all_y_pred_rf, labels=all_class_ids,
        target_names=le.classes_, zero_division=0
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
    df = pd.read_csv("combined_clean.csv")
    print(f"Loaded combined_clean.csv: {len(df)} rows across {df['session'].nunique()} sessions.")

    le = LabelEncoder()
    df["label_encoded"] = le.fit_transform(df["label"])
    y = df["label_encoded"]

    all_y_true, all_y_pred_rf = run_loso_cross_validation(df, le)

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
    plt.title("Grouped LOSO-CV Confusion Matrix (Random Forest)")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=150)
    plt.close()

    importances = pd.Series(clf_final.feature_importances_, index=FEATURES).sort_values()
    plt.figure(figsize=(7, 4))
    importances.plot(kind="barh", color="#2b5c8f")
    plt.title("Feature Importance (Random Forest)")
    plt.xlabel("Gini Importance")
    plt.tight_layout()
    plt.savefig("feature_importance.png", dpi=150)
    plt.close()

    joblib.dump(clf_final, "model.joblib")
    joblib.dump(le, "label_encoder.joblib")

    print("\nSaved model artifacts:")
    print("  - model.joblib")
    print("  - label_encoder.joblib")
    print("  - confusion_matrix.png")
    print("  - feature_importance.png")


if __name__ == "__main__":
    main()
