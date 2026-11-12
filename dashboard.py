"""
dashboard.py - Real-Time Streamlit IDS Monitoring Dashboard
"""

import json
import time
from pathlib import Path
import streamlit as st

try:
    import serial
except ImportError:
    serial = None

st.set_page_config(
    page_title="IoT Edge IDS Monitor",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent
JSON_PATH = BASE_DIR / "latest_prediction.json"
BAUD_RATE = 115200

st.title("🛡️ IoT Edge Intrusion Detection System")
st.caption("Live edge telemetry monitoring with AES-128-GCM + Random Forest IDS")

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