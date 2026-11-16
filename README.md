# AI-Driven Green Cybersecurity Framework for Automotive Wireless Sensor Networks

This project is a prototype intrusion-detection system for automotive wireless sensor networks. ESP32 boards send encrypted sensor readings to a receiver, and a Python machine-learning model classifies traffic as normal, flood, replay, or tamper. A Streamlit dashboard displays live predictions and sensor data, and can send demo-mode commands to the sender.

## Requirements

- Python 3.10 or newer
- Two ESP32 boards and the sensors used by the firmware (ACS712, BME280, and PIR)
- Arduino IDE with ESP32 board support and the Adafruit BME280 libraries
- A USB connection from the receiver to your computer

The sender's USB connection is also needed to use the dashboard's attack-mode controls. The trained model files are included in the repository.

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

   Open the local URL printed by Streamlit in your browser. To use the dashboard's sender controls, select the sender's serial port in the dashboard and close any other program using that port.

## Optional: train the model

The included model is ready for live monitoring. To train a new model, put labeled capture CSV files in `data/`, then run:

```bash
python clean_data.py
python train_model.py
```

The new model artifacts are saved in the project folder and used by the live gateway.
