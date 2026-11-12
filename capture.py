import csv
import serial
import sys
import time

port, label = sys.argv[1], sys.argv[2]
out = f"{label}_{int(time.time())}.csv"
s = serial.Serial(port, 115200, timeout=1)
columns = [
    "t_ms", "seq", "auth_ok", "len", "rssi", "iat_ms", "current",
    "temp", "hum", "press", "pir", "replay", "label"
]

with open(out, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(columns)
    while True:
        line = s.readline().decode(errors="ignore").strip()
        if not line or not line[0].isdigit():
            continue

        fields = line.split(",")
        # Current receiver records include replay as the 12th field. Accept
        # older 11-field records too, marking their replay status as unknown/0.
        if len(fields) == 11:
            fields.append("0")
        if len(fields) == 12:
            writer.writerow(fields + [label])
            f.flush()
