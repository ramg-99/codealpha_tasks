# Network Packet Analyzer

## Overview

This project was developed as part of a Cyber Security Internship to understand packet capture and basic network traffic analysis using Python.

The application captures network packets and displays useful information such as source IP address, destination IP address, and protocol type.

---

## Objectives

* Capture network traffic packets
* Analyze packet structure
* Understand network communication flow
* Learn basics of network protocols
* Display useful packet information

---

## Technologies Used

* Python
* Scapy
* Virtual Environment (venv)
* VS Code
* GitHub

---

## Features

* Capture live network packets
* Extract Source IP Address
* Extract Destination IP Address
* Detect protocol type (TCP / UDP / Other)
* Analyze network traffic

---

## Project Structure

```plaintext
network_packet_analyzer/
│
├── packet_capture.py
├── interfaces.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Installation

### 1. Create Virtual Environment

```bash
python -m venv venv
```

### 2. Activate Virtual Environment

Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install scapy
```

### 4. Save Dependencies

```bash
pip freeze > requirements.txt
```

---

## Run the Project

Execute:

```bash
python packet_capture.py
```

Generate network traffic by:

* Opening websites
* Refreshing browser pages
* Running:

```bash
ping 8.8.8.8
```

---

## Sample Output

```plaintext
Capturing packets...

================
Source IP: 10.183.121.1
Destination IP: 185.199.110.133
Protocol: TCP

================
Source IP: 142.xx.xx.xx
Destination IP: 10.xx.xx.xx
Protocol: TCP
Payload:xxxx

Finished
```

---

## Learning Outcomes

Through this project, I learned:

* Packet capture fundamentals
* Network packet analysis
* Source and destination addressing
* Protocol identification
* Using Python in cybersecurity tasks

---

## Conclusion

This project demonstrates basic packet capture and network analysis using Python and Scapy and helped build practical understanding of networking concepts.
