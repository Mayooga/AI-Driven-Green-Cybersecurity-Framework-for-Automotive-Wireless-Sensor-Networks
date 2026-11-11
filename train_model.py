"""
train_model.py
Step 2 of the pipeline:
- Load combined_clean.csv
- Perform Leave-One-Session-Out Cross Validation (LOSO-CV) across all hardware runs (run1, run2, run3)
- Impute any missing values (decrypt-fail rows) using TRAIN-FOLD-ONLY
  statistics, so no information about the held-out session leaks in
- Benchmark Random Forest against Logistic Regression baseline
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
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import make_pipeline
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
    train_medians = X_train.median(numeric_only=True)
    X_train_filled = X_train.fillna(train_medians)
    X_test_filled = X_test.fillna(train_medians)
    return X_train_filled, X_test_filled


def run_loso_cross_validation(df: pd.DataFrame, le: LabelEncoder):
    """
    Perform Leave-One-Session-Out Cross Validation (LOSO-CV).
    Each session (run1, run2, run3) is held out once as the test set.
    """
    unique_sessions = sorted(df["session"].unique())
    print(f"\n=======================================================")
    print(f" LEAVE-ONE-SESSION-OUT CROSS-VALIDATION (LOSO-CV)")
    print(f" Unique sessions detected: {unique_sessions}")
    if len(unique_sessions) < 4:
        print(f" NOTE: only {len(unique_sessions)} sessions -> report this as a")
        print(f" limitation in the paper (small-N LOSO).")
    print(f"=======================================================\n")

    rf_f1_scores = []
    lr_f1_scores = []

    all_y_true = []
    all_y_pred_rf = []

    for fold_idx, test_session in enumerate(unique_sessions, 1):
        train_df = df[df["session"] != test_session]
        test_df = df[df["session"] == test_session]

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
        macro_f1_rf = f1_score(y_test, pred_rf, average="macro")
        rf_f1_scores.append(macro_f1_rf)

        # 2. Logistic Regression Baseline Model
        clf_lr = make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
        )
        clf_lr.fit(X_train, y_train)
        pred_lr = clf_lr.predict(X_test)
        macro_f1_lr = f1_score(y_test, pred_lr, average="macro")
        lr_f1_scores.append(macro_f1_lr)

        print(f"--- Fold {fold_idx} (Held-out Test Session: {test_session}) ---")
        print(f"  Train samples: {len(train_df)} | Test samples: {len(test_df)}")
        print(f"  Random Forest Macro-F1     : {macro_f1_rf:.4f}")
        print(f"  Logistic Regression Macro-F1: {macro_f1_lr:.4f}\n")

        all_y_true.extend(y_test)
        all_y_pred_rf.extend(pred_rf)

    mean_rf = np.mean(rf_f1_scores)
    std_rf = np.std(rf_f1_scores)
    mean_lr = np.mean(lr_f1_scores)
    std_lr = np.std(lr_f1_scores)

    print("=======================================================")
    print(" LOSO-CV BENCHMARK SUMMARY FOR PAPER")
    print("=======================================================")
    print(f" Random Forest Overall Macro-F1     : {mean_rf:.4f} \u00b1 {std_rf:.4f}")
    print(f" Logistic Regression Overall Macro-F1: {mean_lr:.4f} \u00b1 {std_lr:.4f}")
    print(f" RF Improvement over Baseline       : +{(mean_rf - mean_lr)*100:.2f}%\n")

    print("=== Aggregated Classification Report (Random Forest) ===")
    print(classification_report(all_y_true, all_y_pred_rf, target_names=le.classes_))

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

    if df["session"].nunique() > 1:
        all_y_true, all_y_pred_rf = run_loso_cross_validation(df, le)
    else:
        print("Single session detected. Running standard 75/25 split.")
        all_y_true, all_y_pred_rf = None, None

    # Train final Random Forest on ALL sessions (for deployment).
    # Impute with the full-dataset median here -- this is fine because
    # this final model is not being evaluated on held-out data, it's the
    # artifact you ship.
    X_full = df[FEATURES].fillna(df[FEATURES].median(numeric_only=True))

    print("Training final Random Forest model on all sessions...")
    clf_final = RandomForestClassifier(
        n_estimators=200, max_depth=8, class_weight="balanced", random_state=42
    )
    clf_final.fit(X_full, y)

    latency_ms, latency_us = measure_latency(clf_final, X_full)
    print(f"\n--- Gateway-Side Inference Latency (host machine, not on-chip) ---")
    print(f" Single Prediction Latency: {latency_us:.2f} \u00b5s ({latency_ms:.4f} ms)")
    print(f" Max Throughput Potential : {int(1000.0 / latency_ms):,} predictions/sec")

    if all_y_true is not None:
        cm = confusion_matrix(all_y_true, all_y_pred_rf)
    else:
        cm = confusion_matrix(y, clf_final.predict(X_full))

    disp = ConfusionMatrixDisplay(cm, display_labels=le.classes_)
    disp.plot(cmap="Blues")
    plt.title("LOSO-CV Confusion Matrix (Random Forest)")
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