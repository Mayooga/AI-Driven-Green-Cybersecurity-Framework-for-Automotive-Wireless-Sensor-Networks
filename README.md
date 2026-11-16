# AI-Driven Green Cybersecurity Framework for Automotive Wireless Sensor Networks

This project is a prototype intrusion-detection system for automotive wireless sensor networks. ESP32 boards send encrypted sensor readings to a receiver, and a Python machine-learning model classifies traffic as normal, flood, replay, or tamper. The Streamlit dashboard displays the latest detection status and security alerts. Attack modes are selected on the sender ESP32 using its F/R/T/N serial controls; the dashboard does not trigger attacks.

## Requirements

- Python 3.10 or newer
- Two ESP32 boards and the sensors used by the firmware (ACS712, BME280, and PIR)
- Arduino IDE with ESP32 board support and the Adafruit BME280 libraries
- A USB connection from the receiver to your computer

The sender's USB connection is used for its serial attack-mode controls. The receiver's USB connection provides telemetry to the gateway. The trained model files are included in the repository.

## Run the project

1. Upload the sketches in `firmware/sender` and `firmware/decryption` to the sender and receiver. Configure the boards' keys and MAC addresses to match your hardware.
2. From the project folder, install the Python packages:

   ```bash
   python -m pip install numpy pandas scikit-learn matplotlib joblib pyserial streamlit
   ```

3. Connect the receiver and find its serial port (for example, `COM5` on Windows). Close Arduino Serial Monitor for that port.
4. Open two terminals in the project folder. In the first, start the gateway, replacing `COM5` with your receiver port:

   ```bash
   python live_gateway.py COM5
   ```

5. In the second terminal, start the dashboard:

   ```bash
   streamlit run dashboard.py
   ```

   Open the local URL printed by Streamlit in your browser. The dashboard shows the current IDS status and recent alerts. Use the sender ESP32 serial interface to select F (flood), R (replay), T (tamper), or N (normal); the dashboard reports the resulting detections from the receiver gateway.

## Optional: train the model

The included model is ready for live monitoring. To train a new model, put labeled capture CSV files in `data/`, then run:

```bash
python clean_data.py
python train_model.py
```

The new model artifacts are saved in the project folder and used by the live gateway.
