# ESP32 IoT Intrusion Detection System

This project sends sensor readings between two ESP32 boards using ESP-NOW. A receiver ESP32 decrypts the packets and sends a serial record to a computer. Python scripts collect labeled recordings, prepare features, train and evaluate a Random Forest classifier, and display live predictions in a Streamlit dashboard.

## Project flow

```text
ESP32 sender + sensor -> ESP-NOW -> ESP32 receiver -> USB serial -> Python gateway -> dashboard
                                                            |
Recorded CSVs -> clean_data.py -> combined_clean.csv -> train_model.py -> model artifacts
```

## Hardware and firmware

- Two ESP32 boards: one receiver and one sender.
- An ACS712 current sensor connected to GPIO 34 on the sender (as wired in the sketches).
- USB cables for programming and serial connection.
- Arduino IDE with the ESP32 board support installed.

The receiver sketch is `firmware/decryption/decryption.ino`. Sender sketches are in `firmware/sender`, `firmware/flood_sender`, `firmware/replay_sender`, and `firmware/tamper_sender`.

### Local firmware settings

The repository includes a `secrets.example.h` in each firmware sketch folder. Before compiling a sketch, copy that file to `secrets.h` in the **same folder**. For example, from the project root in PowerShell:

```powershell
Copy-Item firmware/decryption/secrets.example.h firmware/decryption/secrets.h
Copy-Item firmware/sender/secrets.example.h firmware/sender/secrets.h
```

Repeat the sender copy command for `flood_sender`, `replay_sender`, and `tamper_sender` when you use those sketches. Edit the local files with your receiver's MAC address and a shared 16-byte AES key. The sender and receiver must use the same AES key. The sender sketches also need the receiver MAC address. Keep `secrets.h` private; it is excluded by `.gitignore`. Do not upload it. The example headers contain dummy values and must be configured before use.

The key previously used in this project was a predictable demonstration value. Do not treat it as secure. If changing it, change it in the receiver and all sender local settings. This project demonstrates a prototype data path and is not a security-hardened product.

### Upload firmware

1. Open the receiver sketch in Arduino IDE, select the ESP32 board and receiver COM port, and upload it to the receiver board.
2. Get the receiver's Wi-Fi station MAC address. The separate sketch in `mac_adress.ino/mac_adress.ino.ino` prints the board's MAC when run; use the receiver's MAC in each sender's local `secrets.h`.
3. Open one sender sketch, select the sender board and COM port, and upload it to the sender board. Use `sender` for normal traffic, or the matching flood, replay, or tamper sketch for that experiment.
4. Open the receiver's serial connection at **115200 baud** when collecting data or running live detection. Close Arduino IDE Serial Monitor before starting a Python program that reads that same port.

The receiver emits comma-separated lines in this format:

```text
timestamp_ms,packet_size,sensor_value
timestamp_ms,packet_size,DECRYPT_FAIL
```

Startup/status messages are not data records and are skipped by the logger.

## Python setup

Use Python 3.10 or newer. From the project root, create and activate a virtual environment, then install the dependencies:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install pandas numpy scikit-learn matplotlib joblib pyserial streamlit
```

On macOS or Linux, activate the environment with `source .venv/bin/activate` instead. Find the receiver's serial port in Arduino IDE under **Tools > Port** (for example, `COM5` on Windows or `/dev/tty.usbserial-...` on macOS).

## Collect labeled recordings

Collect one CSV per traffic class per independent run. Save the files inside `data/` and use these exact filename patterns because `clean_data.py` derives the label and run/session from the filename:

```text
normal_run1.csv
flood_run1.csv
replay_run1.csv
tamper_run1.csv
normal_run2.csv
...
```

For each recording:

1. Upload the receiver firmware and the sender sketch for the class being recorded.
2. Start the sender and connect the receiver to the computer over USB.
3. In a terminal at the project root, start the logger. Replace `COM5` with the receiver port and use the matching output filename:

   ```powershell
   python log_serial.py COM5 normal data/normal_run1.csv
   ```

   For other classes, change `normal` to `flood`, `replay`, or `tamper`, and change the output file accordingly. The logger's label argument is recorded in the CSV, but the cleaning step uses the filename as the class label.

4. Let the experiment run for a consistent duration or number of packets. Press **Ctrl+C** to stop and save the recording.
5. Repeat the experiment for each class and for multiple independent runs. Keep run numbers consistent across classes (`run1`, `run2`, `run3`, etc.) so evaluation can hold out a run/session at a time. Do not append a new run to an existing filename; use a new run number.

Use the normal sender for normal data and the corresponding attack sender for each attack recording. The replay sketch sends a mix of live and repeated packets; during cleaning, non-repeated records in replay recordings are relabeled as normal. Tampered packets may appear as `DECRYPT_FAIL` in the receiver stream.

Raw CSVs in `data/` are the source recordings. Keep them so the cleaning and training results can be reproduced.

## Clean data and train the model

Run these commands from the project root after collecting the raw CSVs:

```powershell
python clean_data.py
python train_model.py
```

`clean_data.py` reads CSVs from `data/`, sanitizes the receiver output, calculates time-series features within each recording session, and writes `combined_clean.csv`.

`train_model.py` reads `combined_clean.csv`, evaluates a Random Forest using Leave-One-Session-Out cross-validation (and reports a Logistic Regression baseline), then trains the final Random Forest on all collected data. It writes:

- `model.joblib` and `label_encoder.joblib` for live inference.
- `confusion_matrix.png` and `feature_importance.png` for model results.

Keep the model and encoder from the same training run. The live gateway needs both files. The quality of evaluation depends on having multiple independent runs; with only one session, the script falls back to a single-session training path and does not provide a held-out session evaluation.

## Run live detection and dashboard

With the receiver and a sender running, and with `model.joblib` and `label_encoder.joblib` present, open two terminals at the project root. Close Arduino Serial Monitor first.

Terminal 1: start the serial gateway with the receiver's port:

```powershell
python live_gateway.py COM5
```

Terminal 2: launch the dashboard:

```powershell
streamlit run dashboard.py
```

The gateway reads receiver records, computes features, predicts a class, and updates `latest_prediction.json`. The dashboard reads that file and displays the latest class, confidence, packet count, and telemetry. Stop either process with **Ctrl+C**. `latest_prediction.json` is generated while running and is intentionally excluded from Git.

## What to commit to GitHub

Commit the source code, `README.md`, `data/` recordings you are allowed to share, the `secrets.example.h` templates, and the trained model/result files if you want the dashboard to run immediately after cloning. Do not commit any `secrets.h` files. The `.gitignore` excludes local secrets, Python cache/virtual environments, logs, and the live prediction JSON.

If a clone does not include model artifacts, regenerate them by running `clean_data.py` and `train_model.py` after placing the recordings in `data/`.
