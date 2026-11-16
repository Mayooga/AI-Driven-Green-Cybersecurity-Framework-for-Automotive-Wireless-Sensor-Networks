# ESP32 IoT Intrusion Detection System

An ESP32-based wireless sensor network prototype that encrypts sensor telemetry, monitors incoming traffic for intrusion patterns, and displays live predictions in a Streamlit dashboard. The sender transmits current, temperature, humidity, pressure, and motion readings over ESP-NOW. The receiver authenticates and decrypts packets, detects repeated sequence numbers, and forwards telemetry to a Python gateway for machine-learning inference.

## System overview

```text
ACS712 + BME280 + PIR
        │
ESP32 sender ── encrypted ESP-NOW ──> ESP32 receiver ── USB serial ──> Python gateway
    ▲                                                                  │
    └──────── dashboard attack controls (USB serial)                    ├── latest_prediction.json
                                                                       ▼
                                                                  Streamlit dashboard

Recorded serial captures ──> clean_data.py ──> combined_clean.csv ──> train_model.py
                                                                    └── model + evaluation artifacts
```

The sender supports normal, flood, replay, and tamper demonstration modes. The receiver accepts packets from its configured trusted sender, authenticates/decrypts them, rate-limits incoming traffic, and records replay status. Python uses packet timing and sensor-derived features to classify traffic as `normal`, `flood`, `replay`, or `tamper`.

## Hardware and firmware

- Two ESP32 boards: one configured as sender and one as receiver.
- ACS712 current sensor: `OUT` to GPIO 34 (use a voltage divider if the module output can exceed the ESP32 ADC input range).
- BME280: SDA to GPIO 21, SCL to GPIO 22, powered at 3.3 V.
- PIR motion sensor: output to GPIO 27.
- USB connection from the receiver to the computer; a second USB connection to the sender is needed for dashboard attack controls.
- Arduino IDE with ESP32 board support, the Adafruit BME280 library, and its required sensor library installed.

Firmware is in `firmware/sender` and `firmware/decryption`. The shared `sensor_payload.h` defines the encrypted payload: sequence number, current, temperature, humidity, pressure, and PIR state. Keep identical payload definitions on sender and receiver.

### Configure local firmware settings

The repository uses local `secrets.h` files for the AES key, ESP-NOW keys, and receiver MAC configuration. These files are excluded from Git. Configure the sender and receiver with matching keys and the correct peer MAC addresses before compiling. The receiver also has a trusted-sender MAC configured in its sketch; it must match the sender board. Do not commit real keys or device-specific secrets.

### Upload and connect

1. Upload `firmware/decryption/decryption.ino` to the receiver and `firmware/sender/sender.ino` to the sender.
2. Use the MAC addresses printed by the boards at startup to configure their peer settings, including the receiver's trusted-sender setting.
3. Connect the receiver to the computer and note its serial port. Close Arduino IDE Serial Monitor before running a Python process that reads that port.
4. Use **115200 baud** for receiver and sender serial connections.

The receiver prints a header followed by comma-separated records with this schema:

```text
t_ms,seq,auth_ok,len,rssi,iat_ms,current,temp,hum,press,pir,replay
```

Here, `t_ms` is receiver uptime in milliseconds; `seq` is the sender's packet sequence; `auth_ok` reports authentication/decryption success; `len` is the received packet length; `rssi` is received signal strength; `iat_ms` is the inter-arrival time; and `current`, `temp`, `hum`, `press`, and `pir` are the decoded sensor values. `replay` marks a repeated sequence number. Startup and diagnostic lines begin with `#` and are not capture records.

## Python environment

Use Python 3.10 or newer. From the project root:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install pandas numpy scikit-learn matplotlib joblib pyserial streamlit
```

On macOS or Linux, activate with `source .venv/bin/activate`. Find the receiver port in Arduino IDE under **Tools > Port** (for example, `COM5` on Windows or `/dev/ttyUSB0` on Linux).

## Capture labeled data

`capture.py` reads receiver serial records and writes a CSV named with the label and capture timestamp in the project root. Its label argument is stored as the capture label. For example:

```powershell
python capture.py COM5 normal
```

Start the sender in the desired mode, capture a consistent period, and stop the script with **Ctrl+C**. Repeat for `normal`, `flood`, `replay`, and `tamper`, using multiple independent sessions. Rename/move each capture into `data/` using the cleaning pipeline's expected convention:

```text
data/normal_run1.csv
data/flood_run1.csv
data/replay_run1.csv
data/tamper_run1.csv
```

Use a new run number for every independent capture, and keep the run scheme consistent across classes. Do not append separate sessions to one file. The filename supplies the target class and session identifier during cleaning; the `label` column is retained for auditing. Preserve the raw CSVs so preprocessing and model training can be reproduced.

The sender firmware supports serial commands `F`, `R`, `T`, and `N` for flood, replay, tamper, and normal modes. The dashboard can send these commands through the sender's USB serial port. For replay experiments, the sender repeats previously transmitted encrypted packets; receiver replay status is retained as an audit field and is not used as the model's target label.

## Clean data and train

Run from the project root after placing capture CSVs in `data/`:

```powershell
python clean_data.py
python train_model.py
```

`clean_data.py` accepts the receiver's multi-sensor CSV schema, sanitizes timestamps and packet values, labels each row from its capture filename, and computes causal timing/repetition features per capture session. Failed authentication is identified from `auth_ok` and sensor values from those rows are left missing for fold-safe imputation. The cleaned rows are written to `combined_clean.csv`.

`train_model.py` trains a Random Forest classifier for the four traffic classes. It evaluates on grouped held-out data, keeping capture sessions separate for normal/flood/tamper and grouping replay rows by payload identity to avoid identical replay payloads crossing folds. Replay rows still originate from the available replay captures, so this grouping does not establish generalization to independently collected replay attacks. The final model is trained on all available cleaned data.

Generated artifacts:

- `model.joblib` and `label_encoder.joblib` for live inference (keep them from the same training run).
- `feature_medians.joblib` for the final model's missing-value preprocessing.
- `confusion_matrix.png` and `feature_importance.png` for evaluation and interpretation.

Evaluation quality depends on the number and diversity of independent captures. Grouped evaluation is most informative when each class has several sessions and sensor conditions vary between sessions.

## Run live monitoring

With the receiver and sender running and the model artifacts present, use two terminals. Close Serial Monitor on the receiver port before starting the gateway.

Terminal 1 — receiver serial gateway:

```powershell
python live_gateway.py COM5
```

Terminal 2 — dashboard:

```powershell
streamlit run dashboard.py
```

<<<<<<< HEAD
The gateway reads receiver records, computes features, predicts a class, and updates `latest_prediction.json`. In addition to the model output, the file includes an energy profile for the current packet: estimated total energy consumed, energy per packet, security mode, and remaining energy budget. The dashboard reads this data and displays the latest class, confidence, packet count, telemetry, and energy-aware operation state. Stop either process with **Ctrl+C**. `latest_prediction.json` is generated while running and is intentionally excluded from Git.

## Compare sender power modes without a power meter

This separate experiment records sender awake/sleep duty-cycle data and receiver packet counts. It does not measure electrical energy, and its files stay in `green_data/` rather than the attack-training `data/` folder.

1. In `firmware/sender/sender.ino`, set `POWER_MODE` to `MODE_ALWAYS_ON`, `MODE_SLEEP`, or `MODE_ADAPTIVE`, then upload the sketch. Use the sender's normal traffic mode (`N`).
2. Open the sender's Serial Monitor at 115200 baud and the receiver on its own USB serial port. Do not have two programs open on the same COM port.
3. From the project root, run one 10-minute trial (replace `COM5` with the receiver port):

   ```powershell
   python green_capture.py COM5 always_on 1 600
   ```

   When the script says to start the sender, start or reset it in normal mode. At the end, enter the latest sender `# STATS` values for `packets`, `awake_ms`, and `sleep_ms`. Repeat with run numbers 2 and 3, then repeat all three trials for `sleep` and `adaptive`. Keep setup and duration consistent.
4. Summarize the runs:

   ```powershell
   python compare_green.py
   ```

Per-packet receiver logs and the run summary are saved in `green_data/`. `sleep_time_pct` is the share of accounted time spent sleeping; compare it alongside receiver packet counts. It is a duty-cycle proxy only, not Wh, joules, or measured energy savings. Avoid running `clean_data.py` on `green_data/`; this experiment is separate from attack-classifier training.
=======
The gateway reads receiver records, computes the live feature vector used by the trained model, predicts a traffic class, and updates `latest_prediction.json`. The dashboard reads that file to show the latest prediction, confidence, packet counters, and live telemetry. Connect the sender's serial port in the dashboard to use the flood, replay, tamper, and return-to-normal controls. Close Arduino Serial Monitor on the sender port while using those controls.
>>>>>>> 2e79e71ad0ecfb31c9fb07c3c44bad75df49d6ad

Stop either process with **Ctrl+C**. `latest_prediction.json` is generated at runtime and is excluded from Git.

## Repository files

- `firmware/` — ESP32 sender and receiver sketches plus shared sensor payload definitions.
- `data/` — labeled raw capture sessions.
- `capture.py` — receiver serial capture utility.
- `clean_data.py` — capture cleaning and feature engineering.
- `train_model.py` — grouped evaluation and model training.
- `live_gateway.py` — serial gateway and live inference.
- `dashboard.py` — Streamlit telemetry dashboard and sender controls.
