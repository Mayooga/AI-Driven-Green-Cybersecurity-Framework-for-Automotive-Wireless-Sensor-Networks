"""Collect one isolated sender duty-cycle comparison run.

This does not modify the attack-training dataset. It logs receiver packet
records under green_data/ and asks for the sender's final # STATS values.
The result is a duty-cycle proxy, not a measurement of electrical energy.

Usage: python green_capture.py COM5 adaptive 1 600
"""

import csv
import re
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import serial
except ImportError:
    raise SystemExit("pyserial is required. Install with: python -m pip install pyserial")


BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "green_data"
OUT_DIR.mkdir(exist_ok=True)
MODES = {"always_on", "sleep", "adaptive"}
RECEIVER_COLUMNS = [
    "t_ms", "seq", "auth_ok", "len", "rssi", "iat_ms", "current",
    "temp", "hum", "press", "pir", "replay",
]
STATS_RE = re.compile(r"# STATS packets=(\d+) avg_encrypt_us=(\d+) awake_ms=(\d+) sleep_ms=(\d+)")


def main():
    if len(sys.argv) != 5:
        raise SystemExit("Usage: python green_capture.py <receiver_port> <always_on|sleep|adaptive> <run_number> <duration_seconds>")

    port, mode = sys.argv[1], sys.argv[2].lower()
    try:
        run_number, duration_s = int(sys.argv[3]), int(sys.argv[4])
    except ValueError:
        raise SystemExit("run_number and duration_seconds must be integers")
    if mode not in MODES or run_number < 1 or duration_s < 1:
        raise SystemExit("Use a valid mode, run number >= 1, and duration >= 1 second")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"{mode}_run{run_number}_{stamp}"
    packet_path = OUT_DIR / f"{stem}_packets.csv"
    summary_path = OUT_DIR / "runs.csv"
    print(f"Logging receiver on {port} for {duration_s}s. Start sender in NORMAL mode now.")
    try:
        ser = serial.Serial(port, 115200, timeout=0.5)
    except serial.SerialException as exc:
        raise SystemExit(f"Could not open receiver port {port}: {exc}")

    received = authenticated = rejected = replay = 0
    started = time.monotonic()
    with ser, packet_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(RECEIVER_COLUMNS)
        while time.monotonic() - started < duration_s:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not line or not line[0].isdigit():
                continue
            fields = line.split(",")
            if len(fields) == 11:  # receiver firmware without replay column
                fields.append("0")
            if len(fields) != 12:
                continue
            writer.writerow(fields)
            f.flush()
            received += 1
            authenticated += fields[2].strip() == "1"
            rejected += fields[2].strip() == "0"
            replay += fields[11].strip() == "1"

    elapsed = time.monotonic() - started
    print("Capture finished. Read the latest # STATS line from sender Serial Monitor.")
    print("If unavailable, enter 0 for that value; do not substitute receiver counts.")
    try:
        sender_packets = int(input("Sender packets= ").strip() or "0")
        awake_ms = int(input("Sender awake_ms= ").strip() or "0")
        sleep_ms = int(input("Sender sleep_ms= ").strip() or "0")
    except ValueError:
        raise SystemExit("Stats must be integers. Packet log was saved; rerun to add a summary.")

    total_accounted_ms = awake_ms + sleep_ms
    sleep_pct = 100.0 * sleep_ms / total_accounted_ms if total_accounted_ms else ""
    fields = [
        stamp, mode, run_number, duration_s, round(elapsed, 2), sender_packets,
        awake_ms, sleep_ms, round(sleep_pct, 2) if sleep_pct != "" else "",
        received, authenticated, rejected, replay,
        round(received / elapsed, 4) if elapsed else 0,
        packet_path.name,
    ]
    columns = [
        "timestamp", "mode", "run", "target_duration_s", "actual_duration_s",
        "sender_packets_reported", "sender_awake_ms", "sender_sleep_ms",
        "sleep_time_pct", "receiver_records", "authenticated_records",
        "rejected_records", "replay_records", "receiver_records_per_s", "packet_file",
    ]
    write_header = not summary_path.exists()
    with summary_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(columns)
        writer.writerow(fields)
    print(f"Saved packet log: {packet_path}")
    print(f"Added run summary: {summary_path}")
    if sleep_pct != "":
        print(f"Sleep-time share: {sleep_pct:.2f}% (duty-cycle proxy; not measured energy)")


if __name__ == "__main__":
    main()
