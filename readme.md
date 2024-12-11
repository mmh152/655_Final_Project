# SDN-Based DDoS Detection in IoT Networks

This project implements a Software-Defined Networking (SDN) based DDoS attack detection and mitigation system for IoT networks using Contiki-NG. The system uses a combination of rate limiting and traffic pattern analysis to detect and mitigates DDoS attacks while maintaining service for legitimate nodes.

## Prerequisites

- Contiki-NG (latest version)

- Cooja Simulator

- msp430 compiler (`sudo apt-get install gcc-msp430`)

- Python 3.7 or higher

- Ubuntu

## Installation

1. Clone the Contiki-NG repository:

```bash

git clone https://github.com/contiki-ng/contiki-ng.git

cd contiki-ng

```

2. Update the Makefile path:

Open Makefile and update the CONTIKI path to match your system:

```makefile

CONTIKI = /path/to/your/contiki-ng

```

## Building the Project

1. Clean any previous builds:

```bash

make TARGET=cooja clean

```

2. Build each node:

```bash

make TARGET=cooja normal-node

make TARGET=cooja attacker-node

make TARGET=cooja sdn-controller

```

## Running the Simulation

1. Start Cooja simulator:

```bash

cd contiki-ng

./tools/cooja/gradlew run

```

2. Create a new simulation:

   - File → New Simulation

   - Give it a name and click Create

3. Add nodes in this order:

   - 1 SDN Controller (Node 1)

   - 2 Normal Nodes (Nodes 2-3)

   - 1 Attacker Node (Node 4)

4. Position nodes in Cooja:

   - Place SDN Controller in the center

   - Place Normal Nodes within range

   - Place Attacker Node within range but at a different position

## Collecting and Analyzing Results

1. Start the simulation and collect logs:

   - Start simulation

   - Let it run for at least 30 seconds.

2. Save the logs:

   - File → Save data as → Select "Copy to clipboard" or "Save to file"

   - Save as simulation_logs.txt

3. Run analysis script:

```bash

python calculate_metrics.py

```

The script will output:

- Accuracy percentage

- F1-Score

## Detection Methods

The system uses two complementary detection methods:

1. Rate Limiting (Weight: 0.4):

   - Monitors packet rate per node

   - Triggers if rate exceeds threshold

   - RATE_LIMIT_PACKETS = 5 packets/second

2. Pattern Analysis (Weight: 0.6):

   - Uses cosine similarity

   - Compares traffic patterns against baseline

   - DETECTION_THRESHOLD = 0.6

## Configuration

Key parameters in project-conf.h:

```c

#define MAX_NODES 4               // Total nodes in network

#define PACKET_THRESHOLD 10       // Packet count threshold

#define DETECTION_THRESHOLD 0.6   // Similarity threshold

#define BLACKLIST_TIMEOUT 60      // Blacklist duration (seconds)

```
