import pandas as pd
import numpy as np
import time
import threading
import queue
import os
import random
import json
from datetime import datetime, timedelta

# Queue to store processed packet features (same queue used by live capture)
packet_queue = queue.Queue(maxsize=1000)


class MockTrafficGenerator:
    """
    A class that generates mock network traffic data from CSV files or synthetic data.
    This allows for simulating live traffic without actual packet capture.
    """

    def __init__(self, data_dir="data", data_file=None, batch_size=10, delay=0.1):
        """
        Initialize the traffic generator.

        Args:
            data_dir (str): Directory containing traffic data CSV files
            data_file (str): Specific CSV file to use for traffic generation (overrides directory-based loading)
            batch_size (int): Number of packets to process in each batch
            delay (float): Delay between batches in seconds (to simulate real-time)
        """
        self.data_dir = data_dir
        self.data_file = data_file
        self.batch_size = batch_size
        self.delay = delay
        self.running = False
        self.queue = queue.Queue(maxsize=1000)  # Buffer for packets
        self.current_chunk = 0
        self.metadata = None
        self.thread = None
        self.data = None

        # Try to load data from specified file first
        if self.data_file and os.path.exists(self.data_file):
            try:
                print(f"Loading traffic data from {self.data_file}")
                self.data = pd.read_csv(self.data_file)
                print(f"Loaded {len(self.data)} records for traffic simulation")
                # Shuffle the data to ensure randomness in the stream
                self.data = self.data.sample(frac=1).reset_index(drop=True)
                return
            except Exception as e:
                print(f"Error loading data file {self.data_file}: {e}")
                self.data = None

        # If no specific file or loading failed, try metadata or training data
        if not self.data:
            # Try to load metadata
            self.load_metadata()

    def load_metadata(self):
        """Load stream metadata if available."""
        metadata_file = os.path.join(self.data_dir, "stream_metadata.json")
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, "r") as f:
                    self.metadata = json.load(f)
                print(f"Loaded metadata for {len(self.metadata)} stream chunks")
                return True
            except Exception as e:
                print(f"Error loading metadata: {e}")

        print(
            "No stream metadata found, will use training data or generate synthetic data"
        )
        return False

    def load_chunk(self, chunk_index):
        """
        Load a specific chunk of stream data.

        Args:
            chunk_index (int): Index of the chunk to load

        Returns:
            pd.DataFrame: The loaded chunk data or None if not available
        """
        if not self.metadata or chunk_index >= len(self.metadata):
            return None

        chunk_file = os.path.join(self.data_dir, self.metadata[chunk_index]["filename"])
        if os.path.exists(chunk_file):
            try:
                return pd.read_csv(chunk_file)
            except Exception as e:
                print(f"Error loading chunk {chunk_index}: {e}")

        return None

    def load_training_data(self):
        """Load training data if available."""
        train_file = os.path.join(self.data_dir, "network_traffic_train.csv")
        if os.path.exists(train_file):
            try:
                return pd.read_csv(train_file)
            except Exception as e:
                print(f"Error loading training data: {e}")

        return None

    def generate_synthetic_normal(self, num_samples=100):
        """Generate synthetic normal traffic data."""
        data = []
        for _ in range(num_samples):
            # Generate random features for normal traffic
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            source_ip = f"192.168.1.{random.randint(1, 254)}"
            destination_ip = f"10.0.0.{random.randint(1, 254)}"
            src_port = random.randint(49152, 65535)
            dst_port = random.choice([80, 443, 22, 53])
            packet_size = random.randint(64, 1500)
            ttl = random.choice([64, 128, 255])
            flags = random.choice(["", "SYN", "ACK", "SYN-ACK"])
            time_delta = random.uniform(0.001, 0.1)

            data.append(
                {
                    "timestamp": time.time(),
                    "protocol": protocol,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_size": packet_size,
                    "ttl": ttl,
                    "flags": flags,
                    "time_delta": time_delta,
                    "is_anomaly": 0,
                    "anomaly_type": "normal",
                }
            )

        return pd.DataFrame(data)

    def generate_synthetic_anomaly(self, num_samples=10, anomaly_type=None):
        """Generate synthetic anomaly traffic data."""
        data = []

        # Choose an anomaly type if not specified
        if anomaly_type is None:
            anomaly_type = random.choice(
                [
                    "port_scan",
                    "ddos",
                    "data_exfiltration",
                    "brute_force",
                    "malware_communication",
                ]
            )

        # Generate specific anomaly patterns
        if anomaly_type == "port_scan":
            # Port scan has one source scanning multiple ports
            source_ip = f"192.168.1.{random.randint(1, 254)}"
            destination_ip = f"10.0.0.{random.randint(1, 254)}"

            for _ in range(num_samples):
                data.append(
                    {
                        "timestamp": time.time(),
                        "protocol": "TCP",
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "src_port": random.randint(49152, 65535),
                        "dst_port": random.randint(
                            1, 10000
                        ),  # Scanning different ports
                        "packet_size": random.randint(40, 60),  # Small packets
                        "ttl": 64,
                        "flags": "SYN",  # SYN scan
                        "time_delta": random.uniform(0.0001, 0.001),  # Very fast
                        "is_anomaly": 1,
                        "anomaly_type": "port_scan",
                    }
                )

        elif anomaly_type == "ddos":
            # DDoS has multiple sources targeting one destination
            destination_ip = f"10.0.0.{random.randint(1, 254)}"
            dst_port = random.choice([80, 443, 53])

            for _ in range(num_samples):
                data.append(
                    {
                        "timestamp": time.time(),
                        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                        "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                        "destination_ip": destination_ip,
                        "src_port": random.randint(1024, 65535),
                        "dst_port": dst_port,
                        "packet_size": random.randint(40, 100),
                        "ttl": random.choice([32, 64, 128]),
                        "flags": random.choice(["SYN", "ACK", ""]),
                        "time_delta": random.uniform(0.00001, 0.0001),  # Very fast
                        "is_anomaly": 1,
                        "anomaly_type": "ddos",
                    }
                )

        elif anomaly_type == "data_exfiltration":
            # Data exfiltration has large outbound packets
            source_ip = f"192.168.1.{random.randint(1, 254)}"
            destination_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

            for _ in range(num_samples):
                data.append(
                    {
                        "timestamp": time.time(),
                        "protocol": random.choice(["TCP", "UDP"]),
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "src_port": random.randint(49152, 65535),
                        "dst_port": random.choice([80, 443, 22]),
                        "packet_size": random.randint(1000, 1500),  # Large packets
                        "ttl": 64,
                        "flags": "PSH-ACK",
                        "time_delta": random.uniform(0.01, 0.1),
                        "is_anomaly": 1,
                        "anomaly_type": "data_exfiltration",
                    }
                )

        elif anomaly_type == "brute_force":
            # Brute force has repetitive login attempts
            source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            destination_ip = f"10.0.0.{random.randint(1, 254)}"
            dst_port = random.choice([22, 23, 3389])  # SSH, Telnet, RDP

            for _ in range(num_samples):
                data.append(
                    {
                        "timestamp": time.time(),
                        "protocol": "TCP",
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "src_port": random.randint(49152, 65535),
                        "dst_port": dst_port,
                        "packet_size": random.randint(100, 300),
                        "ttl": 64,
                        "flags": "PSH-ACK",
                        "time_delta": random.uniform(0.1, 1.0),  # Somewhat slower
                        "is_anomaly": 1,
                        "anomaly_type": "brute_force",
                    }
                )

        else:  # malware_communication
            # Malware C2 has beaconing patterns
            source_ip = f"192.168.1.{random.randint(1, 254)}"
            destination_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

            for _ in range(num_samples):
                data.append(
                    {
                        "timestamp": time.time(),
                        "protocol": random.choice(["TCP", "UDP", "DNS"]),
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "src_port": random.randint(49152, 65535),
                        "dst_port": random.choice([80, 443, 53, 8080]),
                        "packet_size": random.randint(50, 200),
                        "ttl": 64,
                        "flags": random.choice(["ACK", "PSH-ACK", ""]),
                        "time_delta": random.uniform(50, 70),  # Regular intervals
                        "is_anomaly": 1,
                        "anomaly_type": "malware_communication",
                    }
                )

        return pd.DataFrame(data)

    def start(self):
        """Start the traffic generation thread."""
        if self.running:
            print("Traffic generator is already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._generate_traffic)
        self.thread.daemon = True
        self.thread.start()
        print("Mock traffic generator started")

    def stop(self):
        """Stop the traffic generation thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("Mock traffic generator stopped")

    def _generate_traffic(self):
        """Generate traffic in a separate thread."""
        print("Starting mock traffic generation")

        # If we have pre-loaded data, use it directly
        if self.data is not None:
            total_records = len(self.data)
            position = 0

            while self.running:
                try:
                    # Determine batch size (don't exceed data size)
                    current_batch_size = min(self.batch_size, total_records - position)

                    if current_batch_size <= 0:
                        # Reset position to restart from beginning if we've used all data
                        position = 0
                        current_batch_size = min(self.batch_size, total_records)
                        print("Restarting traffic data from beginning")

                    # Get the next batch
                    batch = self.data.iloc[
                        position : position + current_batch_size
                    ].copy()
                    position += current_batch_size

                    # Add current timestamp to simulate real-time data
                    batch["timestamp"] = time.time()

                    # Process and add batch to queue
                    self._process_chunk(batch)

                    # Sleep to simulate real-time traffic
                    time.sleep(self.delay)

                except Exception as e:
                    print(f"Error generating traffic: {e}")
                    time.sleep(1)

            return

        # If no pre-loaded data, use the original chunk-based or synthetic approach
        # First try to use stream chunks if available
        if self.metadata:
            chunk_data = None
            if self.current_chunk < len(self.metadata):
                chunk_data = self.load_chunk(self.current_chunk)
                if chunk_data is not None:
                    print(
                        f"Processing stream chunk {self.current_chunk+1}/{len(self.metadata)}"
                    )
                    self._process_chunk(chunk_data)
                    self.current_chunk += 1

                    # Sleep between chunks to simulate real-time
                    time.sleep(self.delay * self.batch_size)
                    return

            # If no chunks or reached the end, try training data
            if self.current_chunk == 0 or (
                self.metadata and self.current_chunk >= len(self.metadata)
            ):
                training_data = self.load_training_data()
                if training_data is not None:
                    print("No more stream chunks, using training data")
                    self._process_chunk(training_data)

                    # Reset to use stream chunks again if available
                    if self.metadata:
                        self.current_chunk = 0

                    # Sleep longer between training data passes
                    time.sleep(self.delay * self.batch_size * 2)
                    return

            # If all else fails, generate synthetic data
            print("No data available, generating synthetic data")
            synthetic_normal = self.generate_synthetic_normal(self.batch_size)
            self._process_chunk(synthetic_normal)

            # Occasionally inject anomalies
            if random.random() < 0.2:  # 20% chance to inject anomaly
                anomaly_count = random.randint(1, 5)
                anomaly_type = random.choice(
                    [
                        "port_scan",
                        "ddos",
                        "data_exfiltration",
                        "brute_force",
                        "malware_communication",
                    ]
                )
                print(f"Injecting {anomaly_count} synthetic {anomaly_type} anomalies")
                synthetic_anomaly = self.generate_synthetic_anomaly(
                    anomaly_count, anomaly_type
                )
                self._process_chunk(synthetic_anomaly)

            # Sleep between synthetic data generation
            time.sleep(self.delay * self.batch_size)

    def _process_chunk(self, chunk_data):
        """Process a chunk of data and add to the queue."""
        # Process in smaller batches to simulate real-time streaming
        for i in range(0, len(chunk_data), self.batch_size):
            if not self.running:
                break

            batch = chunk_data.iloc[i : i + self.batch_size].copy()

            # Add current timestamp to make it "real-time"
            batch["original_timestamp"] = batch["timestamp"]
            batch["timestamp"] = time.time()

            # Add each row to the queue
            for _, row in batch.iterrows():
                packet_dict = row.to_dict()
                try:
                    self.queue.put(packet_dict, block=True, timeout=1)
                except queue.Full:
                    print("Queue is full, dropping packet")

            # Sleep to simulate real-time traffic
            time.sleep(self.delay)

    def get_packet_batch(self, max_batch_size=None):
        """
        Get a batch of packets from the queue.

        Args:
            max_batch_size (int): Maximum number of packets to retrieve

        Returns:
            list: List of packet dictionaries
        """
        if max_batch_size is None:
            max_batch_size = self.batch_size

        packets = []
        start_time = time.time()

        # Try to get up to max_batch_size packets, but don't wait more than 1 second total
        while len(packets) < max_batch_size and time.time() - start_time < 1:
            try:
                packet = self.queue.get(block=True, timeout=0.1)
                packets.append(packet)
                self.queue.task_done()
            except queue.Empty:
                break

        return packets

    def process_packets(self, process_func=None):
        """
        Process packets using the provided function.

        Args:
            process_func (callable): Function to process each packet

        Returns:
            pd.DataFrame: DataFrame of processed packets or None if no packets
        """
        packets = self.get_packet_batch()
        if not packets:
            return None

        # Convert to DataFrame
        df = pd.DataFrame(packets)

        # Apply processing function if provided
        if process_func and callable(process_func):
            df = process_func(df)

        return df

    def generate_large_dataset(
        self,
        num_normal=10000,
        num_anomalies=1000,
        output_file="large_traffic_dataset.csv",
    ):
        """
        Generate a large dataset for training or testing.

        Args:
            num_normal (int): Number of normal traffic records
            num_anomalies (int): Number of anomaly records
            output_file (str): Path to save the dataset

        Returns:
            pd.DataFrame: The generated dataset
        """
        print(
            f"Generating dataset with {num_normal} normal and {num_anomalies} anomaly records..."
        )

        # Generate normal traffic
        normal_df = self.generate_synthetic_normal(num_normal)

        # Generate anomalies of various types
        anomaly_types = [
            "port_scan",
            "ddos",
            "data_exfiltration",
            "brute_force",
            "malware_communication",
        ]
        anomaly_dfs = []

        anomalies_per_type = num_anomalies // len(anomaly_types)
        for anomaly_type in anomaly_types:
            print(f"Generating {anomalies_per_type} {anomaly_type} anomalies")
            anomaly_df = self.generate_synthetic_anomaly(
                anomalies_per_type, anomaly_type
            )
            anomaly_dfs.append(anomaly_df)

        # Combine all data
        all_dfs = [normal_df] + anomaly_dfs
        full_df = pd.concat(all_dfs, ignore_index=True)

        # Sort by timestamp for realistic sequence
        full_df = full_df.sort_values("timestamp").reset_index(drop=True)

        # Save to CSV
        output_path = os.path.join(self.data_dir, output_file)
        full_df.to_csv(output_path, index=False)
        print(f"Dataset saved to {output_path}")

        return full_df


def process_packet_batch(batch_size=100, time_window=60):
    """Process packets in batches for anomaly detection (same as in live_traffic_capture)"""
    packets = []
    start_time = time.time()

    while True:
        # Check if we have enough packets or reached the time window
        if len(packets) >= batch_size or (time.time() - start_time) >= time_window:
            if packets:
                # Convert packet features to DataFrame for processing
                df = pd.DataFrame(packets)

                # Add timestamp for this batch
                batch_timestamp = time.time()
                df["batch_timestamp"] = batch_timestamp

                # Reset for next batch
                packets = []
                start_time = time.time()

                # Return the batch for anomaly detection
                yield df

        # Try to get a packet from the queue with a timeout
        try:
            packet = packet_queue.get(timeout=1)
            packets.append(packet)
        except queue.Empty:
            # No packets available, check if time window is reached
            pass
        except Exception as e:
            print(f"Error getting packet from queue: {e}")


def start_mock_traffic(
    normal_csv=None, anomaly_csv=None, anomaly_ratio=0.1, packets_per_second=10
):
    """Start mock traffic generation in a separate thread"""
    generator = MockTrafficGenerator()
    generator.start()
    return generator


# For testing
if __name__ == "__main__":
    # Generate a larger traffic dataset if it doesn't exist
    if not os.path.exists("mixed_traffic.csv"):
        generator = MockTrafficGenerator()
        generator.generate_large_dataset(normal_count=5000, anomaly_count=500)

    # Start mock traffic generation
    mock_generator = start_mock_traffic(
        normal_csv="mixed_traffic.csv", anomaly_ratio=0.1, packets_per_second=5
    )

    # Process packets in batches (similar to live traffic)
    print("Processing packets in batches...")

    try:
        for i, batch in enumerate(process_packet_batch(batch_size=20, time_window=10)):
            print(f"\nBatch {i+1} with {len(batch)} packets")
            print(
                f"Anomalies in batch: {batch['is_anomaly'].sum() if 'is_anomaly' in batch.columns else 'unknown'}"
            )
            print(batch.head(2))

            if i >= 5:  # Stop after a few batches for testing
                break

    except KeyboardInterrupt:
        print("Stopping mock traffic...")
    finally:
        mock_generator.stop()
        print("Mock traffic stopped")
