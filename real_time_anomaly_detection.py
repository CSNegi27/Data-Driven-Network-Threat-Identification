import pandas as pd
import numpy as np
import threading
import time
import queue
import json
import os
import platform
import logging
import argparse
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from scipy import stats
from joblib import dump, load
from mock_traffic_generator import MockTrafficGenerator

# Initialize logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("anomaly_detector")

# Configure file handler for alerts
alerts_handler = logging.FileHandler("alerts.log", mode="a")
alerts_handler.setLevel(logging.WARNING)
logger.addHandler(alerts_handler)

# Global variables for detection performance metrics
true_positives = 0
false_positives = 0
true_negatives = 0
false_negatives = 0


class AnomalyDetector:
    """
    Real-time anomaly detection using Isolation Forest algorithm.
    """

    def __init__(self, contamination=0.1, n_estimators=100, random_state=42):
        """
        Initialize the anomaly detector.

        Args:
            contamination (float): Expected ratio of anomalies in the data
            n_estimators (int): Number of trees in the forest
            random_state (int): Random seed for reproducibility
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            warm_start=True,  # Allow incremental fitting
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_columns = None
        self.threshold_multiplier = 2.0  # For statistical anomaly detection
        self.normal_data_stats = {}  # For tracking distribution parameters

    def preprocess_features(self, df):
        """
        Extract and normalize features from network traffic data.

        Args:
            df (pd.DataFrame): DataFrame containing packet data

        Returns:
            pd.DataFrame: Preprocessed features ready for anomaly detection
        """
        # Ensure required columns exist
        required_columns = [
            "protocol",
            "source_ip",
            "destination_ip",
            "src_port",
            "dst_port",
            "packet_size",
            "ttl",
        ]

        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Required column '{col}' not found in data")

        # Convert protocol to numeric if it's not already
        if df["protocol"].dtype == "object":
            protocol_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
            df["protocol_num"] = df["protocol"].map(lambda x: protocol_map.get(x, 0))
        else:
            df["protocol_num"] = df["protocol"]

        # Process IP addresses (convert to numeric representation for model)
        df["src_ip_last_octet"] = df["source_ip"].str.split(".").str[-1].astype(int)
        df["dst_ip_last_octet"] = (
            df["destination_ip"].str.split(".").str[-1].astype(int)
        )

        # Process flags if they exist
        if "flags" in df.columns and df["flags"].dtype == "object":
            # Create flag indicators
            df["has_syn"] = df["flags"].str.contains("SYN").fillna(False).astype(int)
            df["has_ack"] = df["flags"].str.contains("ACK").fillna(False).astype(int)
            df["has_psh"] = df["flags"].str.contains("PSH").fillna(False).astype(int)
            df["has_rst"] = df["flags"].str.contains("RST").fillna(False).astype(int)
            df["has_fin"] = df["flags"].str.contains("FIN").fillna(False).astype(int)

        # Create time-based features if time_delta exists
        if "time_delta" in df.columns:
            # Log transform time delta to handle skewed distribution
            df["log_time_delta"] = np.log1p(df["time_delta"])

        # Select features for anomaly detection
        feature_cols = [
            "protocol_num",
            "src_port",
            "dst_port",
            "packet_size",
            "ttl",
            "src_ip_last_octet",
            "dst_ip_last_octet",
        ]

        # Add flag features if they exist
        flag_features = ["has_syn", "has_ack", "has_psh", "has_rst", "has_fin"]
        for feature in flag_features:
            if feature in df.columns:
                feature_cols.append(feature)

        # Add time delta if it exists
        if "log_time_delta" in df.columns:
            feature_cols.append("log_time_delta")

        # Store feature columns for future use
        self.feature_columns = feature_cols

        # Return the features dataframe
        return df[feature_cols]

    def fit(self, df):
        """
        Train the anomaly detection model on initial data.

        Args:
            df (pd.DataFrame): Training data with network traffic

        Returns:
            self: The fitted model
        """
        if df.empty:
            logger.warning("Empty dataframe provided for training")
            return self

        # Preprocess features
        X = self.preprocess_features(df)
        if X.empty:
            logger.warning("No valid features extracted for training")
            return self

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Fit the model
        self.model.fit(X_scaled)

        # Store statistics of normal data for each feature
        for col in X.columns:
            self.normal_data_stats[col] = {
                "mean": X[col].mean(),
                "std": X[col].std(),
                "min": X[col].min(),
                "max": X[col].max(),
            }

        self.is_fitted = True
        logger.info(
            f"Model trained on {len(df)} samples with {len(X.columns)} features"
        )
        return self

    def update(self, df, anomaly_mask=None):
        """
        Update the model with new data (partial_fit).

        Args:
            df (pd.DataFrame): New data
            anomaly_mask (np.ndarray): Boolean mask of known anomalies to exclude from update

        Returns:
            self: The updated model
        """
        if df.empty:
            return self

        # Preprocess features
        X = self.preprocess_features(df)
        if X.empty:
            return self

        # If anomaly_mask is provided, only use normal data for updates
        if anomaly_mask is not None:
            normal_data = X[~anomaly_mask]
            if normal_data.empty:
                return self
            X = normal_data

        # Scale the features
        X_scaled = self.scaler.transform(X)

        try:
            # Update the model (partial fit)
            self.model.set_params(n_estimators=self.model.n_estimators + 10)
            self.model.fit(X_scaled)

            # Update normal data statistics for each feature
            for col in X.columns:
                # Use exponential moving average to update stats
                alpha = 0.1  # Weight for new data
                if col in self.normal_data_stats:
                    self.normal_data_stats[col]["mean"] = (
                        1 - alpha
                    ) * self.normal_data_stats[col]["mean"] + alpha * X[col].mean()
                    self.normal_data_stats[col]["std"] = (
                        1 - alpha
                    ) * self.normal_data_stats[col]["std"] + alpha * X[col].std()
                    self.normal_data_stats[col]["min"] = min(
                        self.normal_data_stats[col]["min"], X[col].min()
                    )
                    self.normal_data_stats[col]["max"] = max(
                        self.normal_data_stats[col]["max"], X[col].max()
                    )
                else:
                    self.normal_data_stats[col] = {
                        "mean": X[col].mean(),
                        "std": X[col].std(),
                        "min": X[col].min(),
                        "max": X[col].max(),
                    }

            logger.debug(f"Model updated with {len(X)} new samples")
        except Exception as e:
            logger.error(f"Error updating model: {e}")

        return self

    def detect_anomalies(self, df):
        """
        Detect anomalies in new data.

        Args:
            df (pd.DataFrame): New data to check for anomalies

        Returns:
            tuple: (anomaly_mask, anomaly_scores, predicted_anomaly_types)
                - anomaly_mask: Boolean array where True indicates anomaly
                - anomaly_scores: Anomaly scores (lower = more anomalous)
                - predicted_anomaly_types: Predicted type of each anomaly
        """
        if df.empty:
            return np.array([]), np.array([]), []

        # Preprocess features
        X = self.preprocess_features(df)
        if X.empty:
            return np.array([]), np.array([]), []

        # If model is not fitted, return empty results
        if not self.is_fitted:
            logger.warning("Model not fitted yet, cannot detect anomalies")
            return (
                np.array([False] * len(df)),
                np.array([1.0] * len(df)),
                ["unknown"] * len(df),
            )

        # Scale the features
        X_scaled = self.scaler.transform(X)

        # Get anomaly scores from Isolation Forest (-1 = anomaly, 1 = normal)
        # Convert to range [0, 1] where lower values indicate anomalies
        raw_scores = self.model.decision_function(X_scaled)
        anomaly_scores = (raw_scores + 1) / 2  # Transform to [0, 1]

        # Determine anomalies using the model's built-in prediction
        # This uses the contamination parameter as threshold
        anomaly_mask = anomaly_scores < 0.5  # Lower scores are more anomalous

        # Identify anomaly types based on feature patterns
        predicted_anomaly_types = self._identify_anomaly_types(df, X, anomaly_mask)

        # Compare with ground truth if available
        if "is_anomaly" in df.columns:
            # Update global metrics
            global true_positives, false_positives, true_negatives, false_negatives

            # Create mask of true anomalies from ground truth
            true_anomaly_mask = df["is_anomaly"] == 1

            # Calculate performance metrics
            tp = np.sum(anomaly_mask & true_anomaly_mask)
            fp = np.sum(anomaly_mask & ~true_anomaly_mask)
            tn = np.sum(~anomaly_mask & ~true_anomaly_mask)
            fn = np.sum(~anomaly_mask & true_anomaly_mask)

            # Update global counters
            true_positives += tp
            false_positives += fp
            true_negatives += tn
            false_negatives += fn

            # Print metrics for this batch
            total = tp + fp + tn + fn
            accuracy = (tp + tn) / total if total > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0
            )

            print(f"\nBatch Detection Performance:")
            print(
                f"  Accuracy: {accuracy:.2f}, Precision: {precision:.2f}, Recall: {recall:.2f}, F1: {f1:.2f}"
            )
            print(f"  TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")

            # Print overall metrics
            total_overall = (
                true_positives + false_positives + true_negatives + false_negatives
            )
            if total_overall > 0:
                accuracy_overall = (true_positives + true_negatives) / total_overall
                precision_overall = (
                    true_positives / (true_positives + false_positives)
                    if (true_positives + false_positives) > 0
                    else 0
                )
                recall_overall = (
                    true_positives / (true_positives + false_negatives)
                    if (true_positives + false_negatives) > 0
                    else 0
                )
                f1_overall = (
                    2
                    * precision_overall
                    * recall_overall
                    / (precision_overall + recall_overall)
                    if (precision_overall + recall_overall) > 0
                    else 0
                )

                print(f"\nOverall Detection Performance:")
                print(
                    f"  Accuracy: {accuracy_overall:.2f}, Precision: {precision_overall:.2f}, Recall: {recall_overall:.2f}, F1: {f1_overall:.2f}"
                )
                print(
                    f"  TP: {true_positives}, FP: {false_positives}, TN: {true_negatives}, FN: {false_negatives}"
                )

        return anomaly_mask, anomaly_scores, predicted_anomaly_types

    def _identify_anomaly_types(self, original_df, feature_df, anomaly_mask):
        """
        Identify the type of each anomaly based on its features.

        Args:
            original_df (pd.DataFrame): Original data with full features
            feature_df (pd.DataFrame): Processed features
            anomaly_mask (np.ndarray): Boolean mask of anomalies

        Returns:
            list: Predicted anomaly type for each record
        """
        anomaly_types = ["unknown"] * len(original_df)

        # If no anomalies, return early
        if not np.any(anomaly_mask):
            return anomaly_types

        # Extract anomalous records for analysis
        anomalous_records = feature_df[anomaly_mask]
        anomalous_indices = np.where(anomaly_mask)[0]

        # Check known anomaly types if available
        if (
            "anomaly_type" in original_df.columns
            and "is_anomaly" in original_df.columns
        ):
            for i, idx in enumerate(anomalous_indices):
                if original_df.iloc[idx]["is_anomaly"] == 1:
                    # Use the ground truth label
                    anomaly_types[idx] = original_df.iloc[idx]["anomaly_type"]
                    continue

        # For each anomaly, try to determine its type
        for i, idx in enumerate(anomalous_indices):
            # Skip if already labeled from ground truth
            if anomaly_types[idx] != "unknown":
                continue

            record = feature_df.iloc[idx]
            orig_record = original_df.iloc[idx]

            # Port scan detection
            if (
                "has_syn" in feature_df.columns
                and record["has_syn"] == 1
                and record["packet_size"] < 100
                and "time_delta" in original_df.columns
                and original_df.iloc[idx]["time_delta"] < 0.01
            ):
                anomaly_types[idx] = "port_scan"
                continue

            # DDoS detection
            if (
                record["packet_size"] < 100
                and (
                    "protocol_num" in feature_df.columns
                    and record["protocol_num"] in [6, 17, 1]
                )  # TCP, UDP, ICMP
                and "time_delta" in original_df.columns
                and original_df.iloc[idx]["time_delta"] < 0.001
            ):
                anomaly_types[idx] = "ddos"
                continue

            # Data exfiltration detection
            if record["packet_size"] > 1000 and (
                "dst_port" in feature_df.columns
                and record["dst_port"] in [80, 443, 22, 8080]
            ):
                anomaly_types[idx] = "data_exfiltration"
                continue

            # Brute force detection
            if (
                "has_psh" in feature_df.columns
                and record["has_psh"] == 1
                and "dst_port" in feature_df.columns
                and record["dst_port"] in [22, 23, 3389, 21, 445]
                and "time_delta" in original_df.columns
                and original_df.iloc[idx]["time_delta"] > 0.1
                and original_df.iloc[idx]["time_delta"] < 2.0
            ):
                anomaly_types[idx] = "brute_force"
                continue

            # Malware communication detection
            if (
                "time_delta" in original_df.columns
                and original_df.iloc[idx]["time_delta"] > 45
                and record["packet_size"] < 300
                and record["packet_size"] > 40
            ):
                anomaly_types[idx] = "malware_communication"
                continue

        return anomaly_types


def get_default_interface():
    """Get the default network interface based on the operating system."""
    system = platform.system().lower()

    if system == "windows":
        try:
            # Try to use the first available interface on Windows
            from scapy.arch.windows import get_windows_if_list

            interfaces = get_windows_if_list()
            if interfaces:
                for interface in interfaces:
                    if (
                        "name" in interface
                        and interface["name"] != "Loopback Pseudo-Interface 1"
                    ):
                        return interface["name"]
                # If no suitable interface found, use the first one anyway
                return interfaces[0]["name"]
        except Exception as e:
            logger.warning(f"Could not get Windows interfaces: {e}")
            # Fallback to common Windows interface names
            return "Ethernet" or "Wi-Fi" or "Wireless Network Connection"
    elif system == "linux":
        # Common Linux interfaces
        return "eth0" or "wlan0" or "ens33"
    elif system == "darwin":  # macOS
        # Common macOS interfaces
        return "en0" or "en1"
    else:
        # Default fallback
        return "eth0"


def process_packet_batch(packets_df, detector):
    """
    Process a batch of packets for anomaly detection.

    Args:
        packets_df (pd.DataFrame): DataFrame of packet data
        detector (AnomalyDetector): Anomaly detector instance

    Returns:
        tuple: (anomaly_mask, anomaly_scores, anomaly_indices, anomaly_types, packets_df)
    """
    # Detect anomalies
    anomaly_mask, anomaly_scores, anomaly_types = detector.detect_anomalies(packets_df)

    # Get indices of anomalies
    anomaly_indices = np.where(anomaly_mask)[0] if len(anomaly_mask) > 0 else []

    # Return results
    return anomaly_mask, anomaly_scores, anomaly_indices, anomaly_types, packets_df


def process_anomalies(packet_queue, alert_queue, detector):
    """
    Process packets from the queue and detect anomalies.
    This function runs in a separate thread.

    Args:
        packet_queue (queue.Queue): Queue of packet batches
        alert_queue (queue.Queue): Queue for anomaly alerts
        detector (AnomalyDetector): Anomaly detector instance
    """
    logger.info("Starting anomaly processing thread")

    while True:
        try:
            # Get packet batch from queue (blocking with timeout)
            packet_batch = packet_queue.get(block=True, timeout=1.0)

            if packet_batch is None:
                # None is a signal to stop the thread
                logger.info("Received stop signal")
                break

            if packet_batch.empty:
                packet_queue.task_done()
                continue

            # Process the batch
            anomaly_mask, anomaly_scores, anomaly_indices, anomaly_types, packets = (
                process_packet_batch(packet_batch, detector)
            )

            # Update model with non-anomalous packets
            if len(anomaly_mask) > 0:
                detector.update(packets, anomaly_mask)

            # Generate alerts for anomalies
            if len(anomaly_indices) > 0:
                for idx in anomaly_indices:
                    packet = packets.iloc[idx]
                    score = anomaly_scores[idx]
                    anomaly_type = anomaly_types[idx]

                    # Determine if this is a known anomaly from ground truth
                    is_known_anomaly = 0
                    if "is_anomaly" in packet and packet["is_anomaly"] == 1:
                        is_known_anomaly = 1

                    # Create alert
                    alert = {
                        "timestamp": time.time(),
                        "score": float(score),
                        "source_ip": packet.get("source_ip", "unknown"),
                        "destination_ip": packet.get("destination_ip", "unknown"),
                        "src_port": int(packet.get("src_port", 0)),
                        "dst_port": int(packet.get("dst_port", 0)),
                        "protocol": packet.get("protocol", "unknown"),
                        "packet_size": int(packet.get("packet_size", 0)),
                        "anomaly_type": anomaly_type,
                        "is_known_anomaly": is_known_anomaly,
                        "details": f"Anomaly score: {score:.4f}",
                    }

                    # Add alert to queue
                    alert_queue.put(alert)

                    # Log the alert
                    logger.warning(json.dumps(alert))

            packet_queue.task_done()

        except queue.Empty:
            # No packets in queue, continue waiting
            continue
        except Exception as e:
            logger.error(f"Error processing packets: {e}")
            time.sleep(1)


def start_anomaly_processing_thread(packet_queue, alert_queue, detector):
    """
    Start the anomaly processing thread.

    Args:
        packet_queue (queue.Queue): Queue of packet batches
        alert_queue (queue.Queue): Queue for anomaly alerts
        detector (AnomalyDetector): Anomaly detector instance

    Returns:
        threading.Thread: The started thread
    """
    thread = threading.Thread(
        target=process_anomalies,
        args=(packet_queue, alert_queue, detector),
        daemon=True,
    )
    thread.start()
    return thread


def main():
    """Main function to start the real-time anomaly detection system."""
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="Real-time network anomaly detection system"
    )
    parser.add_argument(
        "--train_file",
        type=str,
        default="data/network_traffic_train.csv",
        help="Path to training data file",
    )
    parser.add_argument(
        "--monitor_file",
        type=str,
        default="data/network_traffic_test.csv",
        help="Path to monitoring/evaluation data file",
    )
    parser.add_argument(
        "--model_file",
        type=str,
        default="trained_model.joblib",
        help="Path to save/load the trained model",
    )
    parser.add_argument(
        "--train_only",
        action="store_true",
        help="Train the model and exit without monitoring",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.1,
        help="Expected ratio of anomalies in the data",
    )
    args = parser.parse_args()

    print("AI-Driven Threat Detection System")

    # Initialize anomaly detector
    detector = AnomalyDetector(contamination=args.contamination)

    # TRAINING MODE
    if os.path.exists(args.train_file):
        print(f"Loading training data from {args.train_file}")
        train_data = pd.read_csv(args.train_file)

        # Use only normal data for initial training
        normal_data = train_data[train_data["is_anomaly"] == 0]
        print(f"Training model on {len(normal_data)} normal traffic records")
        detector.fit(normal_data)

        # Save the trained model
        print(f"Saving trained model to {args.model_file}")
        dump(detector, args.model_file)

        print("Model training completed")

        # If train_only flag is set, exit after training
        if args.train_only:
            print("Training complete. Exiting as requested.")
            return
    else:
        print(f"Error: Training file {args.train_file} not found!")
        if not os.path.exists(args.model_file):
            print(
                "No trained model found. Cannot proceed without training data or model."
            )
            return

    # MONITORING MODE
    # Load pre-trained model if available and training wasn't just done
    if not detector.is_fitted and os.path.exists(args.model_file):
        print(f"Loading pre-trained model from {args.model_file}")
        detector = load(args.model_file)

    # Create queues for communication between threads
    packet_queue = queue.Queue(maxsize=100)
    alert_queue = queue.Queue(maxsize=100)

    # Start anomaly processing thread
    processing_thread = start_anomaly_processing_thread(
        packet_queue, alert_queue, detector
    )

    # Initialize mock traffic generator with the monitoring file
    print(f"Initializing mock traffic generator with data from {args.monitor_file}")
    traffic_generator = MockTrafficGenerator(
        data_file=args.monitor_file, batch_size=50, delay=0.5
    )
    traffic_generator.start()

    try:
        print("Monitoring network traffic. Press Ctrl+C to stop.")

        while True:
            try:
                # Get packet batch from traffic generator
                df = traffic_generator.process_packets()

                if df is not None and not df.empty:
                    # Put packet batch in queue for processing
                    packet_queue.put(df)

                    # Display a summary of the batch
                    anomaly_count = (
                        df["is_anomaly"].sum() if "is_anomaly" in df.columns else 0
                    )
                    print(
                        f"Processed batch of {len(df)} packets ({anomaly_count} known anomalies)"
                    )

                # Check for alerts
                while not alert_queue.empty():
                    alert = alert_queue.get_nowait()

                    # Determine if this is a true positive based on ground truth
                    if alert.get("is_known_anomaly", 0) == 1:
                        # True positive
                        alert_type = "TRUE POSITIVE"
                    else:
                        # False positive
                        alert_type = "FALSE POSITIVE"

                    print(
                        f"\n[{alert_type}] ALERT: {alert['anomaly_type']} anomaly detected!"
                    )
                    print(f"  Source: {alert['source_ip']}:{alert['src_port']}")
                    print(
                        f"  Destination: {alert['destination_ip']}:{alert['dst_port']}"
                    )
                    print(
                        f"  Protocol: {alert['protocol']}, Size: {alert['packet_size']} bytes"
                    )
                    print(f"  Score: {alert['score']:.4f} (lower is more anomalous)")
                    alert_queue.task_done()

                # Sleep to avoid high CPU usage
                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping anomaly detection system...")
    finally:
        # Stop threads gracefully
        traffic_generator.stop()
        packet_queue.put(None)  # Signal processing thread to stop
        processing_thread.join(timeout=5.0)

        # Print final metrics
        total = true_positives + false_positives + true_negatives + false_negatives
        if total > 0:
            accuracy = (true_positives + true_negatives) / total
            precision = (
                true_positives / (true_positives + false_positives)
                if (true_positives + false_positives) > 0
                else 0
            )
            recall = (
                true_positives / (true_positives + false_negatives)
                if (true_positives + false_negatives) > 0
                else 0
            )
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0
            )

            print("\nFinal Detection Performance:")
            print(f"  Accuracy: {accuracy:.4f}")
            print(f"  Precision: {precision:.4f}")
            print(f"  Recall: {recall:.4f}")
            print(f"  F1 Score: {f1:.4f}")
            print(f"  True Positives: {true_positives}")
            print(f"  False Positives: {false_positives}")
            print(f"  True Negatives: {true_negatives}")
            print(f"  False Negatives: {false_negatives}")

        print("Real-time anomaly detection system stopped")


if __name__ == "__main__":
    main()
