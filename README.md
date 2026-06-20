#  NetSentinel - AI Powered Deep Packet Inspection & Network Threat Detection Platform

NetSentinel is a real-time Deep Packet Inspection (DPI) and Network Threat Detection platform built in C++. It captures live network traffic, performs protocol analysis, extracts DNS and TLS metadata, identifies applications, detects threats, and visualizes security insights through a modern web dashboard.

---

##  Features

### Network Monitoring

* Live packet capture using libpcap
* TCP, UDP, and ICMP traffic analysis
* Flow tracking and connection monitoring
* Top talker identification
* Protocol statistics collection

### Deep Packet Inspection (DPI)

* TLS SNI extraction
* DNS query extraction
* Application identification
* HTTPS traffic analysis
* Domain classification

### Threat Detection Engine

* Port-based IDS rules
* Domain reputation detection
* Malicious IP detection
* Suspicious domain detection
* Port scan detection
* Threat score calculation
* Alert deduplication

### Security Intelligence

* Domain blacklist engine
* IP reputation engine
* Custom security rules
* Severity-based alerting
* Real-time threat monitoring

### Dashboard & APIs

* REST API server
* Modern NetSentinel dashboard
* Real-time updates
* Security overview
* Flow visualization
* Alert management

### Reporting & Analytics

* AI-generated security summaries
* CSV flow export
* JSON flow export
* Application statistics
* Traffic insights

---

#  Architecture

```text
Network Traffic
       │
       ▼
 ┌───────────────┐
 │ libpcap       │
 │ Packet Capture│
 └───────┬───────┘
         │
         ▼
 ┌───────────────┐
 │ Packet Parser │
 └───────┬───────┘
         │
         ▼
 ┌───────────────────────┐
 │ DPI Engine            │
 │                       │
 │ • DNS Extraction      │
 │ • TLS SNI Extraction  │
 │ • App Detection       │
 │ • Flow Tracking       │
 └───────────┬───────────┘
             │
             ▼
 ┌───────────────────────┐
 │ Threat Detector       │
 │                       │
 │ • Port Rules          │
 │ • Domain Rules        │
 │ • IP Rules            │
 │ • Threat Score        │
 └───────────┬───────────┘
             │
             ▼
 ┌───────────────────────┐
 │ REST API Server       │
 └───────────┬───────────┘
             │
             ▼
 ┌───────────────────────┐
 │ NetSentinel Dashboard │
 └───────────────────────┘
```

---

# 📂 Project Structure

```text
Packet_Analyzer/
│
├── include/
│   ├── api_server.h
│   ├── app_tracker.h
│   ├── dns_extractor.h
│   ├── flow_tracker.h
│   ├── protocol_stats.h
│   ├── service_mapper.h
│   ├── sni_extractor.h
│   ├── threat_detector.h
│   ├── top_talker.h
│   └── ...
│
├── src/
│   ├── api_server.cpp
│   ├── app_tracker.cpp
│   ├── dns_extractor.cpp
│   ├── flow_tracker.cpp
│   ├── live_capture.cpp
│   ├── packet_parser.cpp
│   ├── protocol_stats.cpp
│   ├── sni_extractor.cpp
│   ├── threat_detector.cpp
│   └── ...
│
├── rules.txt
├── domains.txt
├── bad_ips.txt
├── flows.csv
├── flows.json
└── README.md
```

---

# 🔍 Detection Capabilities

## Application Detection

NetSentinel identifies:

* YouTube
* Facebook
* Instagram
* Discord
* Telegram
* GitHub
* OpenAI
* Microsoft
* Google
* VS Code Services

---

## Threat Detection

### Malicious IP Detection

```text
[HIGH] Malicious IP
Source: 8.8.8.8
```

### Blocked Domain Detection

```text
[HIGH] Blocked Domain
facebook.com
```

### Suspicious Domain Detection

```text
[MEDIUM] Suspicious Domain
westus-0.in.applicationinsights.azure.com
```

### Port Scan Detection

```text
[HIGH] Port Scan
Host touched multiple ports
```

### Risky Service Detection

```text
TELNET  (23)
FTP     (21)
SMB     (445)
RDP     (3389)
MYSQL   (3306)
```

---

#  AI Security Summary

NetSentinel automatically generates intelligent summaries such as:

```text
Network traffic is primarily TCP-based.

4 unique applications were detected.

2 security alerts detected.

Threat score remains at MEDIUM risk (40/100).

No port scanning activity detected.
```

---

#  REST API Endpoints

## Dashboard

```http
GET /dashboard
```

Returns the NetSentinel web dashboard.

---

## Security Alerts

```http
GET /alerts
```

Example:

```json
[
  {
    "severity":"HIGH",
    "type":"Blocked Domain",
    "source":"192.168.31.44",
    "details":"facebook.com"
  }
]
```

---

## Applications

```http
GET /applications
```

---

## Top Talkers

```http
GET /top-talkers
```

---

## Rules

```http
GET /rules
```

---

## AI Summary

```http
GET /ai-summary
```

---

#  Dashboard Features

### Overview

* Protocol statistics
* Threat score
* AI summary
* Top applications

### Flows

* Active connections
* DNS queries
* Domain tracking

### Alerts

* Security alerts
* Severity levels
* Threat monitoring

### Applications

* Application usage statistics
* Traffic analysis

### Rules

* Active IDS rules
* Domain blocklists
* IP reputation rules

---

# ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/NetSentinel.git
cd NetSentinel
```

### Build

```bash
clang++ -std=c++17 \
-Iinclude \
src/*.cpp \
-lpcap \
-o live_test
```

### Run

```bash
sudo ./live_test
```

---

#  Example Output

```text
=====================================
PROTOCOL STATISTICS
=====================================

TCP  : 145
UDP  : 32
ICMP : 5
TOTAL: 182

=====================================
SECURITY ALERTS
=====================================

[HIGH] Blocked Domain
facebook.com

[HIGH] Malicious IP
8.8.8.8

[MEDIUM] Suspicious Domain
westus-0.in.applicationinsights.azure.com
```

---

#  Technologies Used

* C++
* libpcap
* Multithreading
* Socket Programming
* REST APIs
* HTML
* Tailwind CSS
* JavaScript
* JSON
* CSV Export

---

#  Future Enhancements

* GeoIP Intelligence
* Threat Feed Integration
* SIEM Export
* Email Alerts
* WebSocket Live Updates
* Machine Learning Anomaly Detection
* Groq AI Integration
* Threat Hunting Module

---

#  Author

Vedansh Chandak

Computer Science Engineer | Full Stack Developer | Cybersecurity Enthusiast

Building scalable software, AI-powered systems, and modern security tools.

---

##  If you found this project useful, give it a star on GitHub!
