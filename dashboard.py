"""
dashboard.py - Real-Time Streamlit IDS Monitoring Dashboard
"""

import json
import time
from pathlib import Path
import streamlit as st

st.set_page_config(
    page_title="IoT Edge IDS Monitor",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent
JSON_PATH = BASE_DIR / "latest_prediction.json"

st.title("🛡️ IoT Edge Intrusion Detection System")
st.caption("Live edge telemetry monitoring with AES-128-GCM + Random Forest IDS")

# Initialize persistent session counters
if "counts" not in st.session_state:
    st.session_state.counts = {"normal": 0, "flood": 0, "replay": 0, "tamper": 0}
if "last_seen_packet" not in st.session_state:
    st.session_state.last_seen_packet = 0

placeholder = st.empty()

while True:
    if not JSON_PATH.exists():
        with placeholder.container():
            st.warning("⏳ Waiting for `live_gateway.py` to start transmitting predictions...")
        time.sleep(1)
        continue

    try:
        with open(JSON_PATH, "r") as f:
            data = json.load(f)
    except Exception:
        time.sleep(0.3)
        continue

    latest = data.get("latest", {})
    packet_id = latest.get("packet_count", 0)
    pred_label = str(latest.get("predicted", "normal")).lower()
    confidence = latest.get("confidence", 0.0)
    is_attack = latest.get("is_attack", False)
    feats = latest.get("features", {})
    raw_val = latest.get("raw_value", "N/A")
    updated_at = latest.get("updated_at", "--:--:--")

    # Increment counter only when a new packet arrives
    if packet_id > st.session_state.last_seen_packet:
        st.session_state.last_seen_packet = packet_id
        if pred_label in st.session_state.counts:
            st.session_state.counts[pred_label] += 1

    total_packets = sum(st.session_state.counts.values())

    with placeholder.container():
        # 1. Main Live Status Banner
        if is_attack:
            st.error(f"### 🚨 ATTACK DETECTED: **{pred_label.upper()}** (Confidence: {confidence:.1f}%)")
        else:
            st.success(f"### 🟢 STATUS: **NORMAL TELEMETRY** (Confidence: {confidence:.1f}%)")

        st.caption(f"Packet #{packet_id} | Time: {updated_at} | Sensor Reading: `{raw_val}`")
        st.divider()

        # 2. Live Packet Counters (All 5 Categories)
        st.subheader("📊 Live Packet Counters")
        c_tot, c_norm, c_fld, c_rep, c_tmp = st.columns(5)
        c_tot.metric("📦 Total Packets", total_packets)
        c_norm.metric("🟢 Normal", st.session_state.counts["normal"])
        c_fld.metric("⚡ Flood", st.session_state.counts["flood"])
        c_rep.metric("🔁 Replay", st.session_state.counts["replay"])
        c_tmp.metric("⚠️ Tamper", st.session_state.counts["tamper"])

        st.divider()

        # 3. Live Feature Metrics
        st.subheader("⚡ Live Telemetry Signals")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Inter-Packet Gap", f"{feats.get('inter_packet_ms', 0):.1f} ms")
        m2.metric("Packet Rate", f"{feats.get('packets_per_sec', 0)} pps")
        m3.metric("5-Packet Repeat Rate", f"{feats.get('repeat_rate_5', 0):.2f}")
        m4.metric("Timing Variance (Std)", f"{feats.get('inter_packet_std_5', 0):.1f} ms")

    time.sleep(0.5)