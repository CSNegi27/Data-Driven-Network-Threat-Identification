# Data-Driven-Network-Threat-Identification Using Machine Learning

This project is an AI-driven threat detection system designed to analyze network traffic and identify potential anomalies in real-time. It uses a machine learning model (Isolation Forest) to detect suspicious activities within a network by distinguishing between normal and abnormal traffic patterns.

## Project Structure

- `ai_threat_detection.py`: The main script that trains and tests the anomaly detection model using synthetic network traffic data.
- `generate_synthetic_network_data.py`: Script to generate synthetic network traffic data for training and testing the model.
- `generate_synthetic_traffic.py`: Script to generate synthetic network packets and save them in a .pcap file (Packet Capture).
- `live_traffic_capture.py`: Module for capturing and processing live network traffic.
- `real_time_anomaly_detection.py`: Real-time anomaly detection system that monitors network traffic continuously.
- `dashboard.py`: Interactive web dashboard for visualizing network traffic and anomalies.

## Prerequisites

- Python 3.x
- Required Python libraries (see requirements.txt):
  - numpy
  - pandas
  - scikit-learn
  - scapy
  - joblib
  - dash
  - plotly
  - dash-bootstrap-components
  - matplotlib
  - ipython
  - python-dotenv

You can install the required libraries using pip: `pip install -r requirements.txt`

## How to Run the Project

### Basic Functionality

1. Generate Synthetic Network Traffic Data:

   - Run the `generate_synthetic_network_data.py` script to create synthetic network traffic data.
   - This will generate a CSV file (synthetic_network_data.csv) containing both normal and abnormal traffic data.

   ```bash
   python generate_synthetic_network_data.py
   ```

2. Train and Test the Model:

   - Run the `ai_threat_detection.py` script to train the Isolation Forest model on the synthetic data and evaluate its performance.
   - The script will output the training and testing accuracy along with a classification report.

   ```bash
   python ai_threat_detection.py
   ```

3. Generate Synthetic Network Packets:
   - Run the `generate_synthetic_traffic.py` script to create synthetic network packets and save them in a `.pcap` file.
   - This file can be used for further analysis or as input to network monitoring tools.
   ```bash
   python generate_synthetic_traffic.py
   ```

### Real-time Anomaly Detection (Enhanced Features)

1. Start the Real-time Anomaly Detection System:

   - Run the `real_time_anomaly_detection.py` script to start monitoring network traffic in real-time.
   - This script will capture live network packets, process them, and detect anomalies.
   - Make sure to adjust the network interface in the script to match your system.

   ```bash
   python real_time_anomaly_detection.py
   ```

2. Launch the Interactive Dashboard:
   - Run the `dashboard.py` script to start the web dashboard.
   - Open your browser and navigate to http://127.0.0.1:8050/ to view the dashboard.
   ```bash
   python dashboard.py
   ```

## Project Overview

### Core Components

`ai_threat_detection.py`

- Purpose: Trains an Isolation Forest model to detect anomalies in network traffic.
- Key Steps:
  1. Generates synthetic normal and abnormal network traffic data.
  2. Splits the data into training and testing sets.
  3. Trains the model on the training data.
  4. Evaluates the model using the testing data.
  5. Outputs accuracy and classification metrics.

`generate_synthetic_network_data.py`

- Purpose: Generates synthetic network traffic data, combining normal and abnormal patterns, and saves it as a CSV file.

`generate_synthetic_traffic.py`

- Purpose: Creates synthetic network packets using random IP addresses and TCP ports, saving them as a `.pcap` file for analysis.

### Enhanced Features

`live_traffic_capture.py`

- Purpose: Captures live network packets from a specified interface.
- Key Features:
  1. Uses Scapy to capture and parse packets.
  2. Extracts relevant features from each packet.
  3. Processes packets in batches for efficient analysis.
  4. Runs in a separate thread to prevent blocking.

`real_time_anomaly_detection.py`

- Purpose: Continuously monitors network traffic and detects anomalies in real-time.
- Key Features:
  1. Uses an Isolation Forest model that can be updated incrementally.
  2. Processes network traffic in batches for efficiency.
  3. Generates alerts for detected anomalies.
  4. Logs alerts to a file for further analysis.

`dashboard.py`

- Purpose: Provides a visual interface for monitoring network traffic and anomalies.
- Key Features:
  1. Real-time visualization of network traffic.
  2. Breakdown of traffic by protocol and IP.
  3. Table of recent anomalies with severity indicators.
  4. Auto-refreshing graphs and data.

## Usage

This project can be used as a foundation for developing more advanced network security systems. It demonstrates how machine learning models can be applied to detect potential threats in real-time. The interactive dashboard provides security analysts with a visual interface to monitor network activity and quickly identify potential issues.

## Potential Further Enhancements

- Integrate with external threat intelligence feeds to correlate detected anomalies with known threats.
- Implement more sophisticated machine learning models (LSTM, Autoencoders) for sequence-based anomaly detection.
- Add support for email or SMS notifications when critical anomalies are detected.
- Incorporate netflow/sflow data for more comprehensive network visibility.
- Implement automated response actions for certain types of anomalies.
- Add user authentication and role-based access control to the dashboard.

## Author

