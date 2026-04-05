import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import pandas as pd
import numpy as np
import json
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
import dash_bootstrap_components as dbc

# Maximum number of points to display
MAX_POINTS = 1000

# Data structures for storing streaming data
traffic_data = deque(maxlen=MAX_POINTS)
anomaly_data = deque(maxlen=MAX_POINTS)
traffic_by_protocol = defaultdict(lambda: deque(maxlen=MAX_POINTS))
traffic_by_ip = defaultdict(lambda: deque(maxlen=MAX_POINTS))
anomaly_types = defaultdict(lambda: deque(maxlen=MAX_POINTS))

# Thread lock for data access
data_lock = threading.Lock()


# Function to read alerts from log file
def read_alerts(file_path="alerts.log"):
    alerts = []
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            for line in f:
                try:
                    alert = json.loads(line.strip())
                    alerts.append(alert)
                except json.JSONDecodeError:
                    pass
    return alerts


# Function to update data periodically
def update_data():
    global traffic_data, anomaly_data, traffic_by_protocol, traffic_by_ip, anomaly_types

    while True:
        try:
            # In a real implementation, this would read from a database or message queue
            # For demonstration, we'll generate random data
            timestamp = datetime.now()

            # Simulate network traffic
            normal_traffic = np.random.normal(100, 20, 1)[0]
            anomaly_traffic = (
                np.random.normal(10, 5, 1)[0] if np.random.random() < 0.1 else 0
            )

            protocols = {
                "TCP": np.random.normal(70, 10, 1)[0],
                "UDP": np.random.normal(20, 5, 1)[0],
                "ICMP": np.random.normal(5, 2, 1)[0],
                "Other": np.random.normal(5, 2, 1)[0],
            }

            # Simulate some common IP addresses
            ips = {
                "192.168.1.1": np.random.normal(30, 5, 1)[0],
                "192.168.1.2": np.random.normal(20, 5, 1)[0],
                "192.168.1.3": np.random.normal(15, 3, 1)[0],
                "10.0.0.1": np.random.normal(25, 5, 1)[0],
                "Other": np.random.normal(10, 3, 1)[0],
            }

            # Read real alerts if available
            alerts = read_alerts()

            # Update data structures with thread safety
            with data_lock:
                # Update traffic data
                traffic_data.append(
                    {
                        "timestamp": timestamp,
                        "normal": normal_traffic,
                        "anomaly": anomaly_traffic,
                    }
                )

                # Update protocol data
                for proto, value in protocols.items():
                    traffic_by_protocol[proto].append(
                        {"timestamp": timestamp, "value": value}
                    )

                # Update IP data
                for ip, value in ips.items():
                    traffic_by_ip[ip].append({"timestamp": timestamp, "value": value})

                # Update anomaly data with real alerts if available
                for alert in alerts:
                    if "timestamp" in alert:
                        alert_time = datetime.fromtimestamp(alert["timestamp"])
                        if (timestamp - alert_time) < timedelta(minutes=5):
                            # Add to anomaly data
                            anomaly_data.append(alert)

                            # Track anomaly types
                            if (
                                "anomaly_type" in alert
                                and alert["anomaly_type"] != "unknown"
                            ):
                                anomaly_type = alert["anomaly_type"]

                                # Determine if it's a true or false positive
                                is_true_positive = alert.get("is_known_anomaly", 0) == 1
                                anomaly_type_key = f"{anomaly_type}_{'true' if is_true_positive else 'false'}"

                                # Track counts over time
                                if anomaly_type_key not in anomaly_types:
                                    # Initialize with zeros for past timestamps
                                    for past_time in range(30):
                                        past_timestamp = timestamp - timedelta(
                                            seconds=past_time
                                        )
                                        anomaly_types[anomaly_type_key].append(
                                            {"timestamp": past_timestamp, "value": 0}
                                        )

                                # Add the current anomaly
                                anomaly_types[anomaly_type_key].append(
                                    {"timestamp": timestamp, "value": 1}
                                )

                            # Track "unknown" anomalies
                            elif "is_known_anomaly" in alert:
                                is_true_positive = alert.get("is_known_anomaly", 0) == 1
                                anomaly_type_key = (
                                    f"unknown_{'true' if is_true_positive else 'false'}"
                                )

                                # Add the current anomaly
                                if anomaly_type_key not in anomaly_types:
                                    # Initialize with zeros for past timestamps
                                    for past_time in range(30):
                                        past_timestamp = timestamp - timedelta(
                                            seconds=past_time
                                        )
                                        anomaly_types[anomaly_type_key].append(
                                            {"timestamp": past_timestamp, "value": 0}
                                        )

                                anomaly_types[anomaly_type_key].append(
                                    {"timestamp": timestamp, "value": 1}
                                )

            # Sleep for a second before next update
            time.sleep(1)
        except Exception as e:
            print(f"Error updating data: {e}")
            time.sleep(1)


# Start data update thread
update_thread = threading.Thread(target=update_data, daemon=True)
update_thread.start()

# Initialize the Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

app.layout = dbc.Container(
    [
        dbc.Row(
            [
                dbc.Col(
                    [
                        html.H1(
                            "Network Traffic Anomaly Dashboard",
                            className="text-center text-primary mb-4",
                        ),
                        html.Hr(),
                    ],
                    width=12,
                )
            ]
        ),
        dbc.Row(
            [
                dbc.Col(
                    [
                        dbc.Card(
                            [
                                dbc.CardHeader("Traffic Overview"),
                                dbc.CardBody(
                                    [
                                        dcc.Graph(id="traffic-graph"),
                                        dcc.Interval(
                                            id="traffic-interval",
                                            interval=1000,  # in milliseconds
                                            n_intervals=0,
                                        ),
                                    ]
                                ),
                            ]
                        )
                    ],
                    width=12,
                )
            ]
        ),
        dbc.Row(
            [
                dbc.Col(
                    [
                        dbc.Card(
                            [
                                dbc.CardHeader("Traffic by Protocol"),
                                dbc.CardBody(
                                    [
                                        dcc.Graph(id="protocol-graph"),
                                        dcc.Interval(
                                            id="protocol-interval",
                                            interval=1000,  # in milliseconds
                                            n_intervals=0,
                                        ),
                                    ]
                                ),
                            ]
                        )
                    ],
                    width=6,
                ),
                dbc.Col(
                    [
                        dbc.Card(
                            [
                                dbc.CardHeader("Traffic by IP"),
                                dbc.CardBody(
                                    [
                                        dcc.Graph(id="ip-graph"),
                                        dcc.Interval(
                                            id="ip-interval",
                                            interval=1000,  # in milliseconds
                                            n_intervals=0,
                                        ),
                                    ]
                                ),
                            ]
                        )
                    ],
                    width=6,
                ),
            ]
        ),
        dbc.Row(
            [
                dbc.Col(
                    [
                        dbc.Card(
                            [
                                dbc.CardHeader("Anomaly Types"),
                                dbc.CardBody(
                                    [
                                        dcc.Graph(id="anomaly-types-graph"),
                                        dcc.Interval(
                                            id="anomaly-types-interval",
                                            interval=1000,  # in milliseconds
                                            n_intervals=0,
                                        ),
                                    ]
                                ),
                            ]
                        )
                    ],
                    width=12,
                )
            ]
        ),
        dbc.Row(
            [
                dbc.Col(
                    [
                        dbc.Card(
                            [
                                dbc.CardHeader("Recent Anomalies"),
                                dbc.CardBody(
                                    [
                                        html.Div(id="anomalies-table"),
                                        dcc.Interval(
                                            id="anomalies-interval",
                                            interval=2000,  # in milliseconds
                                            n_intervals=0,
                                        ),
                                    ]
                                ),
                            ]
                        )
                    ],
                    width=12,
                )
            ]
        ),
        dbc.Row(
            [
                dbc.Col(
                    [
                        dbc.Card(
                            [
                                dbc.CardHeader("Detection Performance"),
                                dbc.CardBody(
                                    [
                                        html.Div(id="performance-metrics"),
                                        dcc.Interval(
                                            id="performance-interval",
                                            interval=5000,  # in milliseconds
                                            n_intervals=0,
                                        ),
                                    ]
                                ),
                            ]
                        )
                    ],
                    width=12,
                )
            ]
        ),
    ],
    fluid=True,
)


@app.callback(
    Output("traffic-graph", "figure"), [Input("traffic-interval", "n_intervals")]
)
def update_traffic_graph(n):
    with data_lock:
        df = pd.DataFrame(list(traffic_data))

    if df.empty:
        # Return empty figure if no data
        return {"data": [], "layout": go.Layout(title="Network Traffic Over Time")}

    # Create the graph
    return {
        "data": [
            go.Scatter(
                x=df["timestamp"],
                y=df["normal"],
                name="Normal Traffic",
                mode="lines",
                line=dict(color="green"),
            ),
            go.Scatter(
                x=df["timestamp"],
                y=df["anomaly"],
                name="Anomalous Traffic",
                mode="lines",
                line=dict(color="red"),
            ),
        ],
        "layout": go.Layout(
            title="Network Traffic Over Time",
            xaxis=dict(title="Time"),
            yaxis=dict(title="Packets/s"),
            legend=dict(orientation="h", y=1.1),
            margin=dict(l=40, r=20, t=60, b=40),
        ),
    }


@app.callback(
    Output("protocol-graph", "figure"), [Input("protocol-interval", "n_intervals")]
)
def update_protocol_graph(n):
    with data_lock:
        protocols = list(traffic_by_protocol.keys())
        data = []

        for proto in protocols:
            proto_data = list(traffic_by_protocol[proto])
            if proto_data:
                df = pd.DataFrame(proto_data)
                data.append(
                    go.Scatter(
                        x=df["timestamp"], y=df["value"], name=proto, mode="lines"
                    )
                )

    if not data:
        # Return empty figure if no data
        return {"data": [], "layout": go.Layout(title="Traffic by Protocol")}

    # Create the graph
    return {
        "data": data,
        "layout": go.Layout(
            title="Traffic by Protocol",
            xaxis=dict(title="Time"),
            yaxis=dict(title="Packets/s"),
            legend=dict(orientation="h", y=1.1),
            margin=dict(l=40, r=20, t=60, b=40),
        ),
    }


@app.callback(Output("ip-graph", "figure"), [Input("ip-interval", "n_intervals")])
def update_ip_graph(n):
    with data_lock:
        ips = list(traffic_by_ip.keys())
        data = []

        for ip in ips:
            ip_data = list(traffic_by_ip[ip])
            if ip_data:
                df = pd.DataFrame(ip_data)
                data.append(
                    go.Scatter(x=df["timestamp"], y=df["value"], name=ip, mode="lines")
                )

    if not data:
        # Return empty figure if no data
        return {"data": [], "layout": go.Layout(title="Traffic by IP")}

    # Create the graph
    return {
        "data": data,
        "layout": go.Layout(
            title="Traffic by IP",
            xaxis=dict(title="Time"),
            yaxis=dict(title="Packets/s"),
            legend=dict(orientation="h", y=1.1),
            margin=dict(l=40, r=20, t=60, b=40),
        ),
    }


@app.callback(
    Output("anomaly-types-graph", "figure"),
    [Input("anomaly-types-interval", "n_intervals")],
)
def update_anomaly_types_graph(n):
    with data_lock:
        types = list(anomaly_types.keys())
        data = []

        for anomaly_type in types:
            type_data = list(anomaly_types[anomaly_type])
            if type_data:
                df = pd.DataFrame(type_data)

                # Calculate cumulative sum over time
                df["cumulative"] = df["value"].cumsum()

                # Determine color - green for true positives, red for false positives
                color = "green" if "_true" in anomaly_type else "red"

                # Format display name
                display_name = anomaly_type.replace("_true", " (Confirmed)").replace(
                    "_false", " (False)"
                )

                data.append(
                    go.Scatter(
                        x=df["timestamp"],
                        y=df["cumulative"],
                        name=display_name,
                        mode="lines",
                        line=dict(color=color),
                    )
                )

    if not data:
        # Return empty figure if no data
        return {"data": [], "layout": go.Layout(title="Anomaly Types Over Time")}

    # Create the graph
    return {
        "data": data,
        "layout": go.Layout(
            title="Anomaly Types Over Time (Cumulative)",
            xaxis=dict(title="Time"),
            yaxis=dict(title="Count"),
            legend=dict(orientation="h", y=1.1),
            margin=dict(l=40, r=20, t=60, b=40),
        ),
    }


@app.callback(
    Output("anomalies-table", "children"), [Input("anomalies-interval", "n_intervals")]
)
def update_anomalies_table(n):
    with data_lock:
        alerts = list(anomaly_data)

    if not alerts:
        return html.P("No anomalies detected", className="text-center text-muted")

    # Sort alerts by timestamp (newest first)
    alerts = sorted(alerts, key=lambda x: x.get("timestamp", 0), reverse=True)

    # Create table rows
    rows = []
    for alert in alerts[:10]:  # Show only the 10 most recent
        alert_time = datetime.fromtimestamp(alert.get("timestamp", 0)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        score = alert.get("score", 0)
        source = f"{alert.get('source_ip', 'unknown')}:{alert.get('src_port', 0)}"
        destination = (
            f"{alert.get('destination_ip', 'unknown')}:{alert.get('dst_port', 0)}"
        )

        # Get anomaly type and validation info
        anomaly_type = alert.get("anomaly_type", "Unknown")
        is_confirmed = alert.get("is_known_anomaly", 0) == 1

        # Add row with appropriate color based on score and validation
        severity_class = "table-danger" if score < 0.5 else "table-warning"

        # Override severity class if we know it's a false positive
        if not is_confirmed and "is_known_anomaly" in alert:
            severity_class = "table-secondary"  # Gray for false positives

        rows.append(
            html.Tr(
                [
                    html.Td(alert_time),
                    html.Td(f"{score:.4f}"),
                    html.Td(source),
                    html.Td(destination),
                    html.Td(anomaly_type),
                    html.Td(
                        "✓" if is_confirmed else "✗",
                        className="text-success" if is_confirmed else "text-danger",
                    ),
                ],
                className=severity_class,
            )
        )

    # Create the table
    return dbc.Table(
        [
            html.Thead(
                html.Tr(
                    [
                        html.Th("Time"),
                        html.Th("Score"),
                        html.Th("Source"),
                        html.Th("Destination"),
                        html.Th("Type"),
                        html.Th("Confirmed"),
                    ]
                )
            ),
            html.Tbody(rows),
        ],
        striped=True,
        bordered=True,
        hover=True,
    )


@app.callback(
    Output("performance-metrics", "children"),
    [Input("performance-interval", "n_intervals")],
)
def update_performance_metrics(n):
    with data_lock:
        alerts = list(anomaly_data)

    if not alerts:
        return html.P(
            "No data available for performance metrics",
            className="text-center text-muted",
        )

    # Calculate detection performance metrics
    true_positives = sum(
        1
        for a in alerts
        if a.get("is_known_anomaly", 0) == 1 and a.get("score", 1) < 0.8
    )
    false_positives = sum(
        1
        for a in alerts
        if a.get("is_known_anomaly", 0) == 0 and a.get("score", 1) < 0.8
    )
    true_negatives = sum(
        1
        for a in alerts
        if a.get("is_known_anomaly", 0) == 0 and a.get("score", 1) >= 0.8
    )
    false_negatives = sum(
        1
        for a in alerts
        if a.get("is_known_anomaly", 0) == 1 and a.get("score", 1) >= 0.8
    )

    # Calculate metrics
    total = true_positives + false_positives + true_negatives + false_negatives

    if total == 0:
        return html.P(
            "Insufficient data for performance metrics",
            className="text-center text-muted",
        )

    accuracy = (true_positives + true_negatives) / total if total > 0 else 0
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
    f1_score = (
        2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    )

    # Create the metrics cards
    return dbc.Row(
        [
            dbc.Col(
                [
                    dbc.Card(
                        [
                            dbc.CardBody(
                                [
                                    html.H4(
                                        f"{accuracy:.2%}",
                                        className="text-center text-info",
                                    ),
                                    html.P(
                                        "Accuracy", className="text-center text-muted"
                                    ),
                                ]
                            )
                        ]
                    )
                ],
                width=3,
            ),
            dbc.Col(
                [
                    dbc.Card(
                        [
                            dbc.CardBody(
                                [
                                    html.H4(
                                        f"{precision:.2%}",
                                        className="text-center text-success",
                                    ),
                                    html.P(
                                        "Precision", className="text-center text-muted"
                                    ),
                                ]
                            )
                        ]
                    )
                ],
                width=3,
            ),
            dbc.Col(
                [
                    dbc.Card(
                        [
                            dbc.CardBody(
                                [
                                    html.H4(
                                        f"{recall:.2%}",
                                        className="text-center text-warning",
                                    ),
                                    html.P(
                                        "Recall", className="text-center text-muted"
                                    ),
                                ]
                            )
                        ]
                    )
                ],
                width=3,
            ),
            dbc.Col(
                [
                    dbc.Card(
                        [
                            dbc.CardBody(
                                [
                                    html.H4(
                                        f"{f1_score:.2%}",
                                        className="text-center text-primary",
                                    ),
                                    html.P(
                                        "F1 Score", className="text-center text-muted"
                                    ),
                                ]
                            )
                        ]
                    )
                ],
                width=3,
            ),
        ]
    )


if __name__ == "__main__":
    app.run(debug=True)
