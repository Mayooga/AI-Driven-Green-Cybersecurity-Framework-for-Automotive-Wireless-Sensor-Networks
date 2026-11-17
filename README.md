# AI-Driven Green Cybersecurity Framework for Automotive Wireless Sensor Networks

This project is a prototype intrusion-detection system for a wireless sensor network built with two ESP32 boards. The sender collects current, environmental, and motion readings and transmits them over ESP-NOW. The receiver authenticates/decrypts packets, checks sender identity and sequence numbers, and sends packet records to a host computer over USB serial. A Python Random Forest model classifies traffic as `normal`, `flood`, `replay`, or `tamper`. A Streamlit dashboard shows predictions and green-mode trial information and can control sender demonstration modes.

The receiver-to-dashboard data path is:

```text
Sensors → ESP32 sender → encrypted ESP-NOW → ESP32 receiver
                                              │ USB serial
                                              ▼
                                      live_gateway.py
                                              │
                                              ▼
                                   latest_prediction.json
                                              │
                                              ▼
                                      dashboard.py
```

The dashboard does not read the receiver serial stream directly. The gateway owns the receiver COM port and writes `latest_prediction.json`; Streamlit reads that JSON file. The dashboard uses a separate sender COM port for attack-mode controls. The receiver port can be opened by only one program at a time, so close Arduino Serial Monitor before running the gateway or a capture tool on that port.

## Project contents

- `firmware/sender/` — sender sketch and shared sensor payload definition.
- `firmware/decryption/` — receiver sketch and shared sensor payload definition.
- `capture.py` — captures labeled receiver serial records to CSV.
- `clean_data.py` — validates and preprocesses labeled captures and engineers causal features.
- `model_features.py` — shared model feature order used by training and live inference.
- `train_model.py` — grouped model evaluation, final model training, and artifact generation.
- `live_gateway.py` — receiver serial parsing, live feature generation, prediction, and JSON output.
- `dashboard.py` — live monitoring, sender controls, and green-mode trial display.
- `green_capture.py` — records packet and sender duty-cycle data for green-mode trials.
- `compare_green.py` — summarizes green-mode trials.
- `data/` — attack-class training recordings, named by class and run.
- `green_data/` — separate green-mode packet captures and trial summaries.

## Hardware and wiring

- Two ESP32 development boards compatible with ESP-NOW and the required GPIO/light-sleep features.
- ACS712 current sensor: `OUT` to sender GPIO 34. The assembled prototype connects this output directly, without a voltage divider. The firmware records the raw ADC value; note the exact 5 A or 20 A module variant used because it does not convert ADC values into calibrated current.
- BME280: SDA to GPIO 21, SCL to GPIO 22, and 3.3 V supply. The firmware checks I²C addresses `0x76` and `0x77`.
- PIR sensor: output to GPIO 27; ensure its output voltage is safe for the ESP32 input.
- USB data connection from the receiver to the host computer. A second USB connection from the sender is needed for dashboard controls and to read sender statistics during green-mode trials.

The sender averages 16 ACS712 ADC samples. It reads BME280 temperature, humidity, and pressure and a binary PIR state. These readings and a 16-bit sequence number form the packed 11-byte sensor payload.

## Software requirements

- Python 3.10 or newer.
- Arduino IDE with ESP32 board support.
- Arduino libraries: Adafruit BME280 and Adafruit Unified Sensor. ESP-NOW, Wi-Fi, Wire/I²C, Preferences, light-sleep support, and mbedTLS are provided by the ESP32 Arduino core.
- Python packages: `numpy`, `pandas`, `scikit-learn`, `matplotlib`, `joblib`, `pyserial`, and `streamlit`.

AVR board support is not required by the current firmware. The repository does not pin exact Arduino IDE, ESP32 board package, or Python package versions; record the installed versions when preparing reproducible project documentation.

## 1. Get the project ready

Open a terminal in the project root. Create and activate a Python virtual environment and install the packages:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install numpy pandas scikit-learn matplotlib joblib pyserial streamlit
```

On macOS/Linux, create the environment with `python3 -m venv .venv` and activate it with `source .venv/bin/activate`. Install the same packages using `python -m pip install ...`.

The repository does not include public `secrets.h` templates. The firmware folders need local `secrets.h` files, and `.gitignore` excludes them. If you cloned the repository, create each file locally using your private configuration. Do not commit or share the files or their key values.

The sender `secrets.h` must define the following arrays with the correct values and sizes. This illustrates the required names and lengths only; populate every byte with your own matching configuration before compiling. Do not use zero-filled or example keys:

```cpp
static const uint8_t receiverMac[6] = { /* receiver station MAC */ };
static const uint8_t aesKey[16] = { /* shared AES-128 key */ };
static const uint8_t espNowPmk[16] = { /* ESP-NOW PMK */ };
static const uint8_t espNowLmk[16] = { /* ESP-NOW LMK */ };
```

The receiver `secrets.h` must define matching `aesKey[16]`, `espNowPmk[16]`, and `espNowLmk[16]` arrays. Use the same key bytes on both devices. The receiver's trusted sender address is separately configured in `firmware/decryption/decryption.ino` as `trustedSenderMac`; set it to the sender station MAC. Configure keys with unique, unpredictable values and keep them private.

## 2. Configure and upload ESP32 firmware

1. Connect the receiver by USB and open `firmware/decryption/decryption.ino` in Arduino IDE. Select a compatible ESP32 board and the receiver's COM port.
2. Upload the receiver sketch. Open Serial Monitor at **115200 baud** and note the line beginning `# Receiver MAC:`.
3. Connect the sender. Open `firmware/sender/sender.ino`, select the sender board and port, and set `receiverMac` in the sender's local `secrets.h` to the receiver MAC. Upload the sender sketch and note its `# Sender station MAC:` line.
4. Set the receiver sketch's `trustedSenderMac` to the sender's station MAC. Ensure the AES key, ESP-NOW PMK, and LMK match between sender and receiver. Re-upload the receiver sketch after editing its trusted MAC.
5. Restart the sender. Confirm its startup messages show the expected power mode and payload size. The receiver should print its CSV header and then data rows for processed packets.

The receiver record schema is:

```text
t_ms,seq,auth_ok,len,rssi,iat_ms,current,temp,hum,press,pir,replay
```

`auth_ok=0` identifies an authentication failure; its sensor fields are placeholders and must not be treated as valid readings. Authenticated replay packets are logged with `replay=1` for audit/training, but the receiver rejects them as accepted telemetry.

The receiver CSV columns mean: `t_ms` receiver uptime, `seq` sender sequence number, `auth_ok` AES-GCM verification result, `len` application packet length, `rssi` received signal strength, `iat_ms` inter-arrival time, `current/temp/hum/press/pir` the decoded sensor measurements, and `replay` the receiver's sequence-number replay flag. Startup and diagnostic lines start with `#` and are not data rows.

The application packet layout is `12-byte IV || 11-byte ciphertext || 16-byte GCM tag`. ESP-NOW peer encryption is configured in addition to AES-128-GCM payload protection. The receiver checks sender MAC, packet length, per-source/global packet rate, GCM authentication, and sequence freshness. These mechanisms are prototype controls, not a complete security certification.

The sender starts in normal mode. It supports serial commands `N`, `F`, `R`, and `T` for normal, flood, replay, and tamper. The dashboard can send these commands. Replay and tamper require at least one normal authenticated packet to be transmitted first. Flood mode transmits high-rate test traffic; replay mode retransmits recent authenticated packets; tamper mode modifies packet data so AES-GCM authentication fails.

## 3. Run live monitoring

Make sure the model artifacts exist in the project root: `model.joblib`, `label_encoder.joblib`, and `feature_medians.joblib`. They are included with this project. If you retrain, regenerate all three together.

1. Close Arduino Serial Monitor on the **receiver** port.
2. In a terminal with the virtual environment active, start the gateway. Replace `COM5` with the receiver's port:

   ```powershell
   python live_gateway.py COM5
   ```

3. In a second terminal, start Streamlit:

   ```powershell
   streamlit run dashboard.py
   ```

4. Open the local URL printed in the terminal. The dashboard will read the latest gateway state from `latest_prediction.json` and refresh its live panels.
5. To use attack controls, connect the **sender's** COM port in the dashboard. Close Serial Monitor or any other program using that sender port. Use the buttons to select a mode and return to Normal after each experiment.

The receiver COM port must remain available to the gateway while live monitoring is running. `green_capture.py` also needs the receiver port, so stop the gateway before starting a green-mode capture. `latest_prediction.json` is generated at runtime and is ignored by Git.

## 4. Capture labeled model-training data

The checked-in training captures are stored under `data/` and use one file per class/session. To collect an additional run:

1. Connect the receiver to the computer and identify its COM port.
2. Start the sender in the class you want to record. Use the dashboard's sender controls or a serial terminal on the sender port. Keep the receiver capture process and sender control on their separate ports.
3. Close Arduino Serial Monitor on the **receiver** port. Start `capture.py` with the receiver COM port and class label. Example:

   ```powershell
   python capture.py COM5 normal
   ```

   Use `flood`, `replay`, or `tamper` for the other classes.
4. Let the scenario run for the desired duration. Press **Ctrl+C** to end the capture; rows are flushed as they are written.
5. `capture.py` writes a file named like `normal_<timestamp>.csv` in the project root. Move it into `data/` and rename it using the exact session pattern expected by cleaning, such as `normal_run6.csv`.
6. Repeat for independent sessions. Use `normal_runN.csv`, `flood_runN.csv`, `replay_runN.csv`, and `tamper_runN.csv`; do not append a new session to an existing file or overwrite source captures.

`clean_data.py` determines the label and session from each filename, not from the receiver's `replay` decision. The checked-in dataset currently has five files per class. More diverse independent sessions improve the value of held-out evaluation.

## 5. Clean data and train the model

Run these commands from the project root after adding or changing captures:

```powershell
python clean_data.py
python train_model.py
```

`clean_data.py` reads `data/*.csv`, sanitizes timestamps and packet sizes, marks failed-authentication current readings as missing, labels rows from filenames, and calculates causal timing/repetition features per session. It writes `combined_clean.csv`.

`train_model.py` evaluates the Random Forest using Leave-One-Group-Out folds. Normal, flood, and tamper are held out by complete session. Replay is grouped by payload signature to keep duplicate replay payloads from crossing folds. Median imputation for each fold is calculated from the training partition only. The script prints grouped F1 and pooled classification metrics and saves:

- `model.joblib` — trained Random Forest.
- `label_encoder.joblib` — mapping between class names and encoded labels.
- `feature_medians.joblib` — final-model imputation values used by live inference.
- `confusion_matrix.png` and `feature_importance.png` — evaluation plots.

Keep the model, label encoder, and feature medians from the same training run. The shared nine-feature order is defined in `model_features.py`. Although the ESP32 collects current, temperature, humidity, pressure, and PIR, the current Random Forest uses the ACS712 current value plus timing, repetition, and packet-size features; the other sensor channels are retained in captures but are not direct model inputs.

The model inputs are inter-packet interval, five-record interval variability, packet rate in a trailing one-second window, ACS712 current reading, rolling current z-score, repeated-reading indicator, five-record repeat rate, repeat/timing interaction, and packet size. Feature windows are causal and reset at each capture session. Receiver authentication and replay flags are retained for audit; capture filenames provide the class labels, and the flags are not direct model features.

Replay evaluation prevents identical payloads from crossing folds, but replay samples still come from the available replay sessions. Report this limitation when interpreting generalization results. Do not report training-set performance as held-out performance.

## 6. Run the green-mode experiment

The sender's `POWER_MODE` is a compile-time setting in `firmware/sender/sender.ino`. Available modes are `MODE_ALWAYS_ON`, `MODE_SLEEP`, and `MODE_ADAPTIVE`; the source defaults to adaptive. To compare modes, change the macro to the desired mode and compile/upload the sender firmware for each condition. `green_capture.py` records the mode name passed on its command line but does **not** change or verify the sender firmware setting.

For each mode:

1. Set `POWER_MODE` to the desired mode, compile and upload the sender sketch, and confirm its startup message.
2. Open Serial Monitor on the **sender** port at 115200 baud before the trial and allow any USB-triggered reset to finish. If you need trial-aligned sender counters, restart the sender immediately before the trial and confirm its startup output; `# STATS` counters reset at boot. Put it in Normal mode and leave the monitor connected to read stats.
3. Stop `live_gateway.py` and close Arduino Serial Monitor on the **receiver** port.
4. Start a trial with the receiver port, mode label, run number, and duration in seconds. Example:

   ```powershell
   python green_capture.py COM5 adaptive 1 120
   ```

5. During the trial, read the latest `# STATS` line on the sender's separate port. The firmware prints stats every 20 packets; if no fresh stats line appears during a short or slow-mode trial, enter `0` for unavailable values. When the capture ends, enter the sender's `packets`, `awake_ms`, and `sleep_ms` values when prompted; do not substitute receiver counts.
6. Repeat for `always_on`, `sleep`, and `adaptive`, using comparable durations and conditions. Store separate run numbers for repeated trials.
7. Summarize the trials:

   ```powershell
   python compare_green.py
   ```

The tools save packet captures and `runs.csv` under `green_data/`. The dashboard displays these summaries. `sleep_time_pct` is a duty-cycle proxy calculated from sender awake/sleep counters; neither it nor the gateway's software energy estimate is a direct measurement of electrical energy. Use external voltage/current instrumentation for quantitative energy-consumption or energy-saving claims.

## Troubleshooting

- **Port access denied / gateway receives no records:** close Serial Monitor and any other process using the receiver COM port. Confirm the receiver baud rate is 115200.
- **Sender controls do not respond:** close other programs using the sender COM port, confirm the selected port, and wait for the sender's wake/ready handshake. Replay/tamper need a normal packet first.
- **No authenticated receiver rows:** check sender/receiver MAC configuration, matching AES and ESP-NOW keys, peer encryption setup, and that both boards run the compatible sketches.
- **BME280 warning:** check 3.3 V and I²C wiring and confirm the module responds at `0x76` or `0x77`. If unavailable, the firmware sets BME payload readings to zero.
- **Gateway reports missing or mismatched model artifacts:** run `python clean_data.py` and `python train_model.py`, then ensure the three model artifacts are from the same training run.
- **Capture does not appear in training:** ensure the CSV is in `data/` and named `<class>_run<number>.csv`, using `normal`, `flood`, `replay`, or `tamper`.
- **Green-mode values look implausible:** verify that the flashed `POWER_MODE` matches the mode label, restart the sender counters before each trial, and compare trials of similar duration. These values are counters and duty-cycle proxies, not power-meter readings.

## Security and reproducibility notes

The prototype demonstrates encrypted telemetry, receiver authentication/replay checks, traffic limiting, supervised classification, and low-power operating modes. It is not a production-hardened security product. Keep key material private, record the hardware/software versions and experiment conditions, and avoid claiming measured energy savings without physical energy measurements.
