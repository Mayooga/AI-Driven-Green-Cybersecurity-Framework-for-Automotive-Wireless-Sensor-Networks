"""
dashboard.py - Real-Time Streamlit IDS Monitoring Dashboard
"""

import json
import time
from pathlib import Path
import pandas as pd
import streamlit as st

try:
    import serial
except ImportError:
    serial = None

st.set_page_config(
    page_title="Green Cybersecurity Framework",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent
JSON_PATH = BASE_DIR / "latest_prediction.json"
GREEN_DIR = BASE_DIR / "green_data"
RUNS_PATH = GREEN_DIR / "runs.csv"
BAUD_RATE = 115200

st.markdown("""
<style>
    .stApp, [data-testid="stAppViewContainer"] { background: #070b09; color: #e5f2e9; }
    [data-testid="stHeader"] { background: rgba(7,11,9,.96); }
    [data-testid="stSidebar"] { background: #0b110e; border-right: 1px solid #193526; }
    h1, h2, h3, p, label, [data-testid="stMarkdownContainer"] { color: #e5f2e9; }
    [data-testid="stMetric"] { background: #101813; border: 1px solid #21452e;
        padding: 14px 16px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,.22); }
    [data-testid="stMetricLabel"] { color: #9bb8a3; }
    [data-testid="stMetricValue"] { color: #63e68a; }
    [data-testid="stDataFrame"], [data-testid="stTable"] { background: #101813; border: 1px solid #21452e; border-radius: 10px; }
    [data-testid="stAlert"] { background: #101813; border: 1px solid #21452e; color: #e5f2e9; }
    [data-baseweb="input"] > div, [data-baseweb="select"] > div, textarea {
        background: #101813; color: #e5f2e9; border-color: #31583b; }
    .stButton > button { background: #39c96a; color: #061009; border: 1px solid #55e681; border-radius: 9px; font-weight: 700; }
    .stButton > button:hover { background: #62e68a; color: #061009; border-color: #8af0a7; }
    hr { border-color: #20372a; }
    .hero { padding: 24px 28px; border-radius: 16px; color: white;
        background: linear-gradient(115deg,#050806,#0c2817 58%,#174b2a); border: 1px solid #28663a; margin: 0 0 18px 0; }
    .hero h1 { color: #76f39a; margin: 0; font-size: 2rem; }
    .hero p { color: #c5e8ce; margin: 8px 0 0 0; font-size: 1rem; }
    .section-note { color: #91b69b; font-size: .9rem; }
</style>
<div class="hero"><h1>AI-Driven Green Cybersecurity Framework</h1>
<p>Automotive wireless sensor networks · Encrypted telemetry · Machine-learning intrusion detection · Energy-aware operation</p></div>
""", unsafe_allow_html=True)

# Initialize persistent session counters
if "counts" not in st.session_state:
    st.session_state.counts = {"normal": 0, "flood": 0, "replay": 0, "tamper": 0}
if "last_seen_packet" not in st.session_state:
    st.session_state.last_seen_packet = 0
if "sender_serial" not in st.session_state:
    st.session_state.sender_serial = None
if "sender_port" not in st.session_state:
    st.session_state.sender_port = ""
if "control_status" not in st.session_state:
    st.session_state.control_status = "Not connected"


def wait_sender_line(sender, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        line = sender.readline().decode("utf-8", errors="ignore").strip()
        if line:
            if line.startswith("# DEMO MODE:"):
                return "mode", line
            if "# UART awake" in line:
                return "awake", line
            if "# CTRL READY" in line:
                return "ready", line
    return None, None


def send_attack_command(sender, command):
    expected = {
        "F": "FLOOD",
        "R": "REPLAY",
        "T": "TAMPER",
        "N": "NORMAL",
    }[command]

    # First try directly; if the sender is asleep, this may only wake it.
    sender.write((command + "\n").encode("ascii"))
    sender.flush()
    kind, line = wait_sender_line(sender, 1.5)
    if kind == "mode" and expected in line:
        return True, line
    if kind == "awake":
        sender.write((command + "\n").encode("ascii"))
        sender.flush()
        kind, line = wait_sender_line(sender, 2.0)
        return kind == "mode" and expected in line, line or "Sender woke but did not confirm the mode"

    # Poll until awake/ready, then issue one clean command. This hides the
    # ESP32 UART wake-character loss from the dashboard user.
    for _ in range(12):
        sender.write(b"?\n")
        sender.flush()
        kind, line = wait_sender_line(sender, 0.5)
        if kind == "awake":
            sender.write(b"?\n")
            sender.flush()
            kind, line = wait_sender_line(sender, 1.0)
        if kind == "ready":
            sender.write((command + "\n").encode("ascii"))
            sender.flush()
            kind, line = wait_sender_line(sender, 2.0)
            return kind == "mode" and expected in line, line or "Sender did not confirm the mode"
        if kind == "mode" and expected in line:
            return True, line
    return False, "No response from sender. Check its COM port and firmware."


st.subheader("Controlled attack demo")
st.caption("Connect the sender USB port here, then use one direct button per attack. Close Serial Monitor on the sender port first.")
sender_port_input = st.text_input("Sender COM port", value=st.session_state.sender_port, placeholder="e.g. COM6")
connect_col, status_col = st.columns([1, 3])
with connect_col:
    if st.button("Connect sender", disabled=(serial is None or not sender_port_input.strip())):
        try:
            if st.session_state.sender_serial is not None:
                st.session_state.sender_serial.close()
            st.session_state.sender_serial = serial.Serial(
                sender_port_input.strip(), BAUD_RATE, timeout=0.1
            )
            st.session_state.sender_port = sender_port_input.strip()
            time.sleep(2.0)  # allow the ESP32 to finish its USB-triggered reset
            st.session_state.control_status = "Connected; sender starts in Normal mode"
        except Exception as exc:
            st.session_state.sender_serial = None
            st.session_state.control_status = f"Connection failed: {exc}"
with status_col:
    st.write(st.session_state.control_status)

if serial is None:
    st.warning("pyserial is required for dashboard attack controls.")
attack_columns = st.columns(4)
for column, (label, command) in zip(
    attack_columns,
    [("Flood", "F"), ("Replay", "R"), ("Tamper", "T"), ("Return to Normal", "N")],
):
    with column:
        if st.button(label, disabled=(st.session_state.sender_serial is None), key=f"attack_{command}"):
            success, message = send_attack_command(st.session_state.sender_serial, command)
            st.session_state.control_status = message
            if success:
                st.success(message)
            else:
                st.error(message)

def render_live_panel():
    if not JSON_PATH.exists():
        st.warning("Waiting for `live_gateway.py` to start transmitting predictions...")
        return

    try:
        with open(JSON_PATH, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        st.info("Waiting for the next complete gateway update...")
        return

    latest = data.get("latest", {})
    packet_id = latest.get("packet_count", 0)
    pred_label = str(latest.get("predicted", "normal")).lower()
    confidence = latest.get("confidence", 0.0)
    is_attack = latest.get("is_attack", False)
    feats = latest.get("features", {})
    raw_val = latest.get("raw_value", "N/A")
    updated_at = latest.get("updated_at", "--:--:--")

    if packet_id > st.session_state.last_seen_packet:
        st.session_state.last_seen_packet = packet_id
        if pred_label in st.session_state.counts:
            st.session_state.counts[pred_label] += 1

    total_packets = sum(st.session_state.counts.values())
    if is_attack:
        st.error(f"### ATTACK DETECTED: **{pred_label.upper()}** (Confidence: {confidence:.1f}%)")
    else:
        st.success(f"### STATUS: **NORMAL TELEMETRY** (Confidence: {confidence:.1f}%)")

    st.caption(f"Packet #{packet_id} | Time: {updated_at} | Sensor Reading: `{raw_val}`")
    st.divider()
    st.subheader("Energy-aware design")
    st.info("The sender supports always-on, fixed-sleep, and adaptive sampling. Gateway energy figures are software estimates; use the Green Mode Experiment below for packet and sleep-duty comparisons.")

    st.divider()
    st.subheader("Live Packet Counters")
    c_tot, c_norm, c_fld, c_rep, c_tmp = st.columns(5)
    c_tot.metric("Total Packets", total_packets)
    c_norm.metric("Normal", st.session_state.counts["normal"])
    c_fld.metric("Flood", st.session_state.counts["flood"])
    c_rep.metric("Replay", st.session_state.counts["replay"])
    c_tmp.metric("Tamper", st.session_state.counts["tamper"])

    st.divider()
    st.subheader("Live Telemetry Signals")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Inter-Packet Gap", f"{feats.get('inter_packet_ms', 0):.1f} ms")
    m2.metric("Packet Rate", f"{feats.get('packets_per_sec', 0)} pps")
    m3.metric("5-Packet Repeat Rate", f"{feats.get('repeat_rate_5', 0):.2f}")
    m4.metric("Timing Variance (Std)", f"{feats.get('inter_packet_std_5', 0):.1f} ms")


# Streamlit fragments refresh telemetry without blocking attack-button clicks.
fragment = getattr(st, "fragment", None)
if fragment is not None:
    render_live_panel = fragment(run_every=0.5)(render_live_panel)
render_live_panel()


def render_green_panel():
    st.divider()
    st.subheader("Green mode experiment")
    st.markdown('<p class="section-note">Live capture and mode comparison · Duty-cycle proxy, not electrical energy measurement</p>', unsafe_allow_html=True)

    summary = pd.DataFrame()
    if RUNS_PATH.exists():
        try:
            summary = pd.read_csv(RUNS_PATH)
        except (OSError, pd.errors.ParserError, pd.errors.EmptyDataError):
            summary = pd.DataFrame()

    packet_files = sorted(GREEN_DIR.glob("*_packets.csv"), key=lambda path: path.stat().st_mtime, reverse=True) if GREEN_DIR.exists() else []
    live_df, live_file = pd.DataFrame(), None
    if packet_files:
        live_file = packet_files[0]
        try:
            live_df = pd.read_csv(live_file)
        except (OSError, pd.errors.ParserError, pd.errors.EmptyDataError):
            live_df = pd.DataFrame()

    modes = ["always_on", "sleep", "adaptive"]
    valid = pd.DataFrame()
    if not summary.empty and {"mode", "receiver_records"}.issubset(summary.columns):
        valid = summary[pd.to_numeric(summary["receiver_records"], errors="coerce").fillna(0) > 0].copy()
    counts = valid["mode"].value_counts() if not valid.empty else pd.Series(dtype=int)
    cols = st.columns(3)
    for col, mode in zip(cols, modes):
        col.metric(mode.replace("_", " ").title() + " valid trials", int(counts.get(mode, 0)))

    if live_file is not None:
        mode_label = live_file.name.split("_run", 1)[0].replace("_", " ").title()
        auth_col = pd.to_numeric(live_df["auth_ok"], errors="coerce") if not live_df.empty and "auth_ok" in live_df else pd.Series(dtype=float)
        last_seq = live_df["seq"].iloc[-1] if not live_df.empty and "seq" in live_df else "—"
        a, b, c, d = st.columns(4)
        a.metric("Latest capture", mode_label)
        b.metric("Packets received", len(live_df))
        c.metric("Authenticated", int((auth_col == 1).sum()))
        d.metric("Latest sequence", last_seq)
        st.caption(f"Live packet file: `{live_file.name}` · Refreshes automatically during capture.")
    else:
        st.caption("No green-mode packet file found yet. Start a run with `green_capture.py` to see live results.")

    required = {"mode", "sleep_time_pct", "receiver_records_per_s", "authenticated_records", "rejected_records"}
    if not valid.empty and required.issubset(valid.columns):
        for name in ["sleep_time_pct", "receiver_records_per_s", "authenticated_records", "rejected_records"]:
            valid[name] = pd.to_numeric(valid[name], errors="coerce")
        averages = valid.groupby("mode", as_index=False).agg(
            trials=("mode", "count"),
            sleep_share_pct=("sleep_time_pct", "mean"),
            received_per_sec=("receiver_records_per_s", "mean"),
            authenticated=("authenticated_records", "mean"),
            rejected=("rejected_records", "mean"),
        )
        st.markdown("**Completed trial averages**")
        shown = averages.rename(columns={
            "mode": "Power mode", "trials": "Valid trials",
            "sleep_share_pct": "Sleep-time share (%)",
            "received_per_sec": "Received packets / sec",
            "authenticated": "Authenticated / run",
            "rejected": "Rejected / run",
        }).round(2)
        st.dataframe(shown, hide_index=True, use_container_width=True)
        st.bar_chart(averages.set_index("mode")["sleep_share_pct"])
        with st.expander("Run-by-run details"):
            detail_cols = [name for name in ["mode", "run", "actual_duration_s", "sender_packets_reported", "sender_awake_ms", "sender_sleep_ms", "sleep_time_pct", "receiver_records", "authenticated_records", "rejected_records"] if name in valid.columns]
            st.dataframe(valid[detail_cols], hide_index=True, use_container_width=True)
    elif not valid.empty:
        st.warning("The run summary is missing fields expected by this dashboard. Check that the current green_capture.py created it.")
    else:
        st.info("Completed trials will appear here after a capture finishes and sender stats are entered. Empty receiver captures are excluded.")


if fragment is not None:
    render_green_panel = fragment(run_every=2.0)(render_green_panel)
render_green_panel()
