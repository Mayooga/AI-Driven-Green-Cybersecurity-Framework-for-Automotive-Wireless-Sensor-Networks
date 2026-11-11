"""
Logs Node B's Serial output straight into a labeled CSV file.

HOW TO USE:
1. Install pyserial once:  pip install pyserial
2. Close Arduino IDE's Serial Monitor for Node B (only one program can read the port at a time)
3. Run this script:  python log_serial.py <PORT> <LABEL> <OUTPUT_FILE>

EXAMPLE:
   python log_serial.py COM5 normal normal_data.csv
   python log_serial.py COM5 flood flood_data.csv
   python log_serial.py COM5 replay replay_data.csv
   python log_serial.py COM5 tamper tamper_data.csv

(On Mac/Linux, the port looks like /dev/tty.usbserial-XXXX instead of COM5.
 Check Arduino IDE's Tools > Port menu to find the exact name.)

Press Ctrl+C to stop logging when you've collected enough rows.
"""

import serial
import sys
import csv
import time

if len(sys.argv) != 4:
    print("Usage: python log_serial.py <PORT> <LABEL> <OUTPUT_FILE>")
    sys.exit(1)

port = sys.argv[1]
label = sys.argv[2]
outfile = sys.argv[3]

ser = serial.Serial(port, 115200, timeout=1)
print(f"Listening on {port}, labeling rows as '{label}'. Press Ctrl+C to stop.")

with open(outfile, "a", newline="") as f:
    writer = csv.writer(f)
    # write header only if file is new/empty
    if f.tell() == 0:
        writer.writerow(["timestamp", "packet_size", "value", "label"])

    try:
        while True:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) == 3:
                parts.append(label)
                writer.writerow(parts)
                f.flush()
                print(parts)
    except KeyboardInterrupt:
        print("\nStopped. Data saved to", outfile)
