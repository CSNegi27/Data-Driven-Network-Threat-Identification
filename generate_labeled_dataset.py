import pandas as pd
import numpy as np
import random
import socket
import struct
import datetime
import os
import json
from sklearn.model_selection import train_test_split
import argparse

# Directory for dataset storage
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

# Constants for dataset generation
NUM_NORMAL_SAMPLES = 10000
NUM_ANOMALY_SAMPLES = 1000
RANDOM_SEED = 42

# Set random seed for reproducibility
np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)


# Helper function to convert numpy types to Python native types
def convert_to_serializable(obj):
    if isinstance(obj, (np.int64, np.int32, np.int16, np.int8)):
        return int(obj)
    elif isinstance(obj, (np.float64, np.float32, np.float16)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_serializable(i) for i in obj]
    else:
        return obj


def generate_ip():
    """Generate a random IP address."""
    return socket.inet_ntoa(struct.pack(">I", random.randint(1, 0xFFFFFFFF)))


def generate_timestamp():
    """Generate a random timestamp within the last day."""
    now = datetime.datetime.now()
    seconds_ago = random.randint(0, 86400)  # Within the last 24 hours
    timestamp = now - datetime.timedelta(seconds=seconds_ago)
    return timestamp.timestamp()


def generate_normal_traffic():
    """Generate normal network traffic patterns."""
    normal_data = []

    # Common protocols
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH"]
    # Typical ports
    common_ports = [80, 443, 22, 53, 21, 25, 110, 143, 993, 995, 3306]

    for _ in range(NUM_NORMAL_SAMPLES):
        timestamp = generate_timestamp()

        # Most traffic is TCP (70%), then UDP (25%), then others (5%)
        protocol = np.random.choice(
            protocols, p=[0.7, 0.25, 0.01, 0.01, 0.01, 0.01, 0.01]
        )

        # IP addresses often follow patterns in normal traffic (internal networks, common services)
        if random.random() < 0.7:  # 70% of traffic is to/from common IPs
            source_ip = f"192.168.1.{random.randint(1, 50)}"  # Internal network
            destination_ip = np.random.choice(
                [
                    "8.8.8.8",  # Google DNS
                    "8.8.4.4",  # Google DNS alternative
                    "172.217.0.0",  # Google
                    "31.13.0.0",  # Facebook
                    "157.240.0.0",  # Facebook alternative
                    generate_ip(),  # Some random IP
                ],
                p=[0.2, 0.05, 0.2, 0.2, 0.05, 0.3],
            )
        else:
            source_ip = generate_ip()
            destination_ip = generate_ip()

        # Port selection based on protocol
        if protocol in ["HTTP", "HTTPS"]:
            src_port = random.randint(49152, 65535)  # Ephemeral ports
            dst_port = 80 if protocol == "HTTP" else 443
        elif protocol == "DNS":
            src_port = random.randint(49152, 65535)
            dst_port = 53
        elif protocol == "SSH":
            src_port = random.randint(49152, 65535)
            dst_port = 22
        else:
            src_port = random.randint(1024, 65535)
            dst_port = (
                np.random.choice(common_ports)
                if random.random() < 0.8
                else random.randint(1, 65535)
            )

        # Packet sizes follow a normal distribution for normal traffic
        if protocol in ["TCP", "HTTP", "HTTPS"]:
            packet_size = int(np.random.normal(500, 200))  # Common web traffic
        elif protocol == "DNS":
            packet_size = int(np.random.normal(100, 50))  # DNS queries are small
        elif protocol == "ICMP":
            packet_size = int(np.random.normal(84, 20))  # ICMP pings
        else:
            packet_size = int(np.random.normal(300, 150))  # Other traffic

        packet_size = max(64, packet_size)  # Minimum packet size

        # Time delta between packets is normally distributed
        if protocol in ["HTTP", "HTTPS"]:
            time_delta = np.random.exponential(0.01)  # Web browsing often has bursts
        else:
            time_delta = np.random.exponential(0.1)  # General traffic

        # TTL values are typically consistent
        ttl = np.random.choice([64, 128, 255])

        # Flags are more predictable in normal traffic
        if protocol == "TCP":
            flags = np.random.choice(
                ["SYN", "ACK", "SYN-ACK", "PSH-ACK", "FIN-ACK"],
                p=[0.1, 0.3, 0.1, 0.4, 0.1],
            )
        else:
            flags = ""

        # Add the sample with a label of 0 (normal)
        normal_data.append(
            {
                "timestamp": timestamp,
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

    return pd.DataFrame(normal_data)


def generate_port_scan_anomaly(num_samples=200):
    """Generate port scan anomaly traffic."""
    port_scan_data = []

    # Port scans typically come from a single source IP to a target IP
    source_ip = generate_ip()
    destination_ip = generate_ip()

    for _ in range(num_samples):
        timestamp = generate_timestamp()
        protocol = "TCP"

        # Port scan hits sequential or common ports
        if random.random() < 0.7:
            # Sequential scan
            base_port = random.randint(1, 65000)
            ports = [base_port + i for i in range(min(5, 65535 - base_port))]
            dst_port = random.choice(ports)
        else:
            # Common ports scan
            dst_port = random.choice(
                [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
            )

        # Port scans usually have a fixed source port
        src_port = random.randint(49152, 65535)

        # Port scans typically use minimal packet sizes (SYN packets)
        packet_size = random.randint(40, 60)

        # Time deltas in port scans are very small (rapid scanning)
        time_delta = np.random.exponential(0.001)

        # TTL is usually consistent
        ttl = 64

        # Most port scans use SYN flags
        flags = "SYN"

        port_scan_data.append(
            {
                "timestamp": timestamp,
                "protocol": protocol,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_size": packet_size,
                "ttl": ttl,
                "flags": flags,
                "time_delta": time_delta,
                "is_anomaly": 1,
                "anomaly_type": "port_scan",
            }
        )

    return pd.DataFrame(port_scan_data)


def generate_ddos_anomaly(num_samples=200):
    """Generate DDoS anomaly traffic."""
    ddos_data = []

    # DDoS typically has multiple source IPs to a single destination
    destination_ip = generate_ip()
    dst_port = random.choice([80, 443, 53, 8080])  # Common target ports

    for _ in range(num_samples):
        timestamp = generate_timestamp()

        # DDoS can use various protocols
        protocol = np.random.choice(["TCP", "UDP", "ICMP"], p=[0.5, 0.3, 0.2])

        # Multiple source IPs
        source_ip = generate_ip()

        # Source ports are random
        src_port = random.randint(1024, 65535)

        # Packet sizes can vary but often similar
        if protocol == "ICMP":
            packet_size = random.randint(76, 108)
        else:
            packet_size = random.randint(40, 120)

        # Time deltas in DDoS are very small (high frequency)
        time_delta = np.random.exponential(0.0001)

        # TTL might vary more in DDoS
        ttl = random.choice([32, 64, 128])

        # Flags in TCP DDoS often SYN (SYN flood)
        if protocol == "TCP":
            flags = random.choice(["SYN", "ACK", "RST"])
        else:
            flags = ""

        ddos_data.append(
            {
                "timestamp": timestamp,
                "protocol": protocol,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_size": packet_size,
                "ttl": ttl,
                "flags": flags,
                "time_delta": time_delta,
                "is_anomaly": 1,
                "anomaly_type": "ddos",
            }
        )

    return pd.DataFrame(ddos_data)


def generate_data_exfiltration_anomaly(num_samples=200):
    """Generate data exfiltration anomaly traffic."""
    exfil_data = []

    # Data exfiltration usually comes from internal to external
    source_ip = f"192.168.1.{random.randint(1, 50)}"
    destination_ip = generate_ip()

    # Often uses common ports to blend in
    dst_port = random.choice([80, 443, 53, 22])

    for _ in range(num_samples):
        timestamp = generate_timestamp()

        # Data exfiltration often uses encrypted protocols
        protocol = np.random.choice(["TCP", "UDP", "HTTPS"], p=[0.4, 0.1, 0.5])

        # Source port usually consistent in a session
        src_port = random.randint(49152, 65535)

        # Data exfiltration has larger outbound packet sizes
        packet_size = int(np.random.normal(1500, 500))
        packet_size = min(max(500, packet_size), 1500)  # Large packets, but within MTU

        # Time deltas vary but often in bursts
        time_delta = np.random.exponential(0.05)

        # TTL usually standard
        ttl = 64

        # TCP flags for data transfer
        if protocol == "TCP" or protocol == "HTTPS":
            flags = "PSH-ACK"
        else:
            flags = ""

        exfil_data.append(
            {
                "timestamp": timestamp,
                "protocol": protocol,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_size": packet_size,
                "ttl": ttl,
                "flags": flags,
                "time_delta": time_delta,
                "is_anomaly": 1,
                "anomaly_type": "data_exfiltration",
            }
        )

    return pd.DataFrame(exfil_data)


def generate_brute_force_anomaly(num_samples=200):
    """Generate brute force attack anomaly traffic."""
    brute_force_data = []

    # Brute force usually targets specific services
    source_ip = generate_ip()
    destination_ip = generate_ip()

    # Common brute force target services
    service = random.choice(["SSH", "FTP", "SMB", "RDP", "HTTP-AUTH"])

    if service == "SSH":
        dst_port = 22
    elif service == "FTP":
        dst_port = 21
    elif service == "SMB":
        dst_port = 445
    elif service == "RDP":
        dst_port = 3389
    else:  # HTTP Auth
        dst_port = random.choice([80, 443])

    for _ in range(num_samples):
        timestamp = generate_timestamp()

        # Protocol based on service
        if service in ["SSH", "FTP", "HTTP-AUTH"]:
            protocol = "TCP"
        elif service == "SMB":
            protocol = "SMB"
        else:
            protocol = "RDP"

        # Source port usually changes with each attempt
        src_port = random.randint(49152, 65535)

        # Packet sizes are generally consistent for login attempts
        packet_size = int(np.random.normal(200, 50))
        packet_size = max(100, packet_size)

        # Time deltas are somewhat regular in brute force
        time_delta = np.random.exponential(0.5)  # Slower to avoid detection

        # TTL standard
        ttl = 64

        # TCP flags for login attempts
        flags = "PSH-ACK"

        brute_force_data.append(
            {
                "timestamp": timestamp,
                "protocol": protocol,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_size": packet_size,
                "ttl": ttl,
                "flags": flags,
                "time_delta": time_delta,
                "is_anomaly": 1,
                "anomaly_type": "brute_force",
            }
        )

    return pd.DataFrame(brute_force_data)


def generate_malware_communication_anomaly(num_samples=200):
    """Generate malware C2 communication anomaly traffic."""
    malware_data = []

    # Malware C2 usually has a specific pattern
    source_ip = f"192.168.1.{random.randint(1, 50)}"  # Infected internal host
    destination_ip = generate_ip()  # C2 server

    # C2 often uses common ports to evade detection
    dst_port = random.choice([80, 443, 53, 8080, 8443])

    # Consistent source port for the session
    src_port = random.randint(49152, 65535)

    for _ in range(num_samples):
        timestamp = generate_timestamp()

        # Malware often uses encrypted or common protocols
        protocol = np.random.choice(["TCP", "HTTPS", "DNS"], p=[0.3, 0.5, 0.2])

        # Packet sizes can be distinctive
        if protocol == "DNS":
            # DNS tunneling has larger queries
            packet_size = int(np.random.normal(300, 100))
        else:
            # Beaconing has consistent sizes
            packet_size = int(np.random.normal(200, 50))

        packet_size = max(64, packet_size)

        # Time deltas in C2 often have a regular pattern
        # Beaconing at regular intervals
        time_delta = abs(
            np.random.normal(60, 5)
        )  # Around every minute with small variation

        # TTL standard
        ttl = 64

        # TCP flags for data transfer
        if protocol == "TCP" or protocol == "HTTPS":
            flags = np.random.choice(["PSH-ACK", "ACK"])
        else:
            flags = ""

        malware_data.append(
            {
                "timestamp": timestamp,
                "protocol": protocol,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_size": packet_size,
                "ttl": ttl,
                "flags": flags,
                "time_delta": time_delta,
                "is_anomaly": 1,
                "anomaly_type": "malware_communication",
            }
        )

    return pd.DataFrame(malware_data)


def create_dataset():
    """Main function to generate network traffic data with labeled anomalies."""
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="Generate labeled network traffic datasets"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/network_traffic.csv",
        help="Output file path for the dataset",
    )
    parser.add_argument(
        "--eval_set",
        action="store_true",
        help="Generate separate training, testing, and evaluation datasets",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=10000,
        help="Total size of the normal traffic dataset",
    )
    parser.add_argument(
        "--anomaly_ratio",
        type=float,
        default=0.1,
        help="Ratio of anomalies to include in the dataset",
    )
    parser.add_argument(
        "--train_ratio",
        type=float,
        default=0.8,
        help="Portion of data to use for training (when splitting)",
    )
    args = parser.parse_args()

    print("Generating labeled network traffic data...")

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    # Calculate dataset sizes
    anomaly_size = int(args.size * args.anomaly_ratio)
    normal_size = args.size

    # Generate normal and anomalous traffic
    print(f"Generating {normal_size} normal traffic records...")
    normal_traffic = generate_normal_traffic()

    print(f"Generating {anomaly_size} anomalous traffic records...")
    anomalies = {
        "port_scan": generate_port_scan_anomaly(int(anomaly_size * 0.2)),
        "ddos": generate_ddos_anomaly(int(anomaly_size * 0.2)),
        "data_exfiltration": generate_data_exfiltration_anomaly(
            int(anomaly_size * 0.2)
        ),
        "brute_force": generate_brute_force_anomaly(int(anomaly_size * 0.2)),
        "malware": generate_malware_communication_anomaly(int(anomaly_size * 0.2)),
    }

    # Combine all anomalies into one DataFrame
    all_anomalies = pd.concat(anomalies.values(), ignore_index=True)

    if args.eval_set:
        # Split data into training, testing, and evaluation sets
        print("Splitting data into training, testing, and evaluation sets...")

        # First split normal traffic into model training/testing and evaluation
        model_normal = normal_traffic.sample(frac=0.6, random_state=42)
        eval_normal = normal_traffic.drop(model_normal.index).reset_index(drop=True)

        # Split model data into train and test
        train_normal = model_normal.sample(frac=args.train_ratio, random_state=42)
        test_normal = model_normal.drop(train_normal.index).reset_index(drop=True)

        # Split anomalies into test and evaluation sets
        model_anomalies = all_anomalies.sample(frac=0.5, random_state=42)
        eval_anomalies = all_anomalies.drop(model_anomalies.index).reset_index(
            drop=True
        )

        # Combine into final datasets
        train_data = train_normal  # Training data is normal traffic only
        test_data = pd.concat([test_normal, model_anomalies], ignore_index=True)
        eval_data = pd.concat([eval_normal, eval_anomalies], ignore_index=True)

        # Shuffle the testing and evaluation data
        test_data = test_data.sample(frac=1, random_state=42).reset_index(drop=True)
        eval_data = eval_data.sample(frac=1, random_state=42).reset_index(drop=True)

        # Save datasets
        train_file = os.path.join(
            os.path.dirname(args.output), "network_traffic_train.csv"
        )
        test_file = os.path.join(
            os.path.dirname(args.output), "network_traffic_test.csv"
        )
        eval_file = os.path.join(
            os.path.dirname(args.output), "network_traffic_eval.csv"
        )

        train_data.to_csv(train_file, index=False)
        test_data.to_csv(test_file, index=False)
        eval_data.to_csv(eval_file, index=False)

        print(f"Saved {len(train_data)} training records to {train_file}")
        print(f"Saved {len(test_data)} testing records to {test_file}")
        print(f"Saved {len(eval_data)} evaluation records to {eval_file}")
    else:
        # Combine all data and save to a single file
        all_data = pd.concat([normal_traffic, all_anomalies], ignore_index=True)
        all_data = all_data.sample(frac=1, random_state=42).reset_index(drop=True)

        all_data.to_csv(args.output, index=False)
        print(f"Saved {len(all_data)} records to {args.output}")

    print("Dataset generation complete.")


if __name__ == "__main__":
    create_dataset()
