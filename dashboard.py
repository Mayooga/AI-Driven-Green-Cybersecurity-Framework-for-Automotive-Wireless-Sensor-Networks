"""Alert-only Streamlit view for the live automotive WSN IDS."""

import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Green Cybersecurity Alerts", page_icon="🔒", layout="wide")

BASE_DIR = Path(__file__).resolve().parent
JSON_PATH = BASE_DIR / "latest_prediction.json"

st.markdown("""
<style>
    .stApp, [data-testid="stAppViewContainer"] { background: #070b09; color: #e5f2e9; }
    [data-testid="stHeader"] { background: rgba(7,11,9,.96); }
    h1, h2, h3, p, [data-testid="stMarkdownContainer"] { color: #e5f2e9; }
    [data-testid="stAlert"] { background: #101813; border: 1px solid #21452e; color: #e5f2e9; }
    [data-testid="stDataFrame"] { background: #101813; border: 1px solid #21452e; border-radius: 10px; }
    .hero { padding: 24px 28px; border-radius: 16px; color: white;
        background: linear-gradient(115deg,#050806,#0c2817 58%,#174b2a); border: 1px solid #28663a; margin-bottom: 18px; }
    .hero h1 { color: #76f39a; margin: 0; font-size: 2rem; }
    .hero p { color: #c5e8ce; margin: 8px 0 0 0; }
</style>
<div class="hero"><h1>AI-Driven Green Cybersecurity Framework</h1>
<p>Automotive wireless sensor network | Live intrusion alerts</p></div>
""", unsafe_allow_html=True)


def render_alerts():
    if not JSON_PATH.exists():
        st.info("Waiting for live predictions from `live_gateway.py`...")
        return

    try:
        with JSON_PATH.open("r", encoding="utf-8") as prediction_file:
            data = json.load(prediction_file)
    except (OSError, json.JSONDecodeError):
        st.info("Waiting for the next complete gateway update...")
        return

    latest = data.get("latest", {})
    label = str(latest.get("predicted", "normal")).lower()
    confidence = float(latest.get("confidence", 0.0))
    packet_id = latest.get("packet_count", "N/A")
    updated_at = latest.get("updated_at", "Unknown time")
    is_attack = bool(latest.get("is_attack", label != "normal"))

    if is_attack:
        st.error(f"## SECURITY ALERT: {label.upper()} detected")
        st.markdown(f"**Confidence:** {confidence:.1f}% | **Packet:** {packet_id} | **Time:** {updated_at}")
    else:
        st.success("## No active threat detected")
        st.caption(f"Latest check: normal | Packet {packet_id} | {updated_at}")

    history = data.get("history", [])
    history_df = pd.DataFrame(history)
    st.divider()
    st.subheader("Network overview")
    if not history_df.empty:
        history_df["predicted"] = history_df["predicted"].fillna("normal").str.lower()
        class_counts = history_df["predicted"].value_counts()
        attacks = int((history_df["predicted"] != "normal").sum())
        metric_cols = st.columns(4)
        metric_cols[0].metric("Packets received", packet_id)
        metric_cols[1].metric("Packets in recent window", len(history_df))
        metric_cols[2].metric("Recent alerts", attacks)
        metric_cols[3].metric("Latest class", label.upper())

        st.caption("Graphs below summarize the most recent gateway history (up to 30 packets).")
        graph_col, rate_col = st.columns(2)
        with graph_col:
            st.markdown("**Classification comparison**")
            comparison = class_counts.reindex(["normal", "flood", "replay", "tamper"], fill_value=0)
            st.bar_chart(comparison)
        with rate_col:
            st.markdown("**Packet rate trend**")
            if "pps" in history_df.columns:
                rate_data = history_df[[column for column in ["packet_count", "time", "pps"] if column in history_df]].copy()
                rate_data["pps"] = pd.to_numeric(rate_data["pps"], errors="coerce")
                if "packet_count" in rate_data:
                    rate_data = rate_data.set_index("packet_count")
                elif "time" in rate_data:
                    rate_data = rate_data.set_index("time")
                st.line_chart(rate_data["pps"])

    alerts = [row for row in history if str(row.get("predicted", "normal")).lower() != "normal"]
    st.divider()
    st.subheader("Recent security alerts")
    if alerts:
        st.dataframe(pd.DataFrame(alerts[::-1]), hide_index=True, use_container_width=True)
    else:
        st.info("No attack alerts in the recent gateway history.")


fragment = getattr(st, "fragment", None)
if fragment is not None:
    render_alerts = fragment(run_every=0.5)(render_alerts)
render_alerts()
