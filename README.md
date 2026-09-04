# Passive Threat Detection for Critical-Infrastructure Networks

## Overview

This project is a **passive AI/ML-based cyber-threat detection pipeline** designed for monitoring critical-infrastructure gateway and peering links where traffic is provided to a secure monitoring environment through a **hardware data diode or passive traffic mirror**.

The central design principle is simple:

> **Observe everything that crosses the monitored link, but never send anything back.**

The system receives a one-directional stream of network traffic and analyzes it in near real time to identify suspicious behavior, classify potential threats, assign confidence/severity scores, and present the resulting intelligence through a monitoring dashboard.

The architecture is intentionally designed so that the detection system does not need to communicate with the original traffic source or destination. This makes it suitable for environments where the monitoring infrastructure must remain isolated from the production network.

---

# Problem Statement

Critical-infrastructure operators need continuous visibility into their gateway and peering traffic. In conventional security architectures, monitoring and detection systems may have access to two-way communication with the monitored network.

For highly sensitive environments, this creates an undesirable risk: if the monitoring or analytics environment is compromised, it could potentially become a pathway into the production network.

The SIH problem therefore requires a threat-detection system that operates on **passively observed, one-directional network traffic**. The system must identify malicious activity without:

- contacting the source or destination,
- performing active probing,
- completing handshakes,
- decrypting protected payloads, or
- sending mitigation commands back into the network.

The required system should ingest traffic, extract useful information, perform detection/classification, and produce actionable security intelligence through structured alerts and a visualization dashboard.

---

# Threats Covered

The project is designed as a common detection platform capable of supporting multiple threat categories:

1. **Volumetric / Protocol DDoS**
   - SYN floods
   - UDP reflection/amplification
   - Spoofed-source floods

2. **Botnet Command-and-Control (C2) Beaconing**
   - Periodic communication
   - Repeated connections to a small set of destinations
   - Abnormal inter-arrival patterns

3. **DGA Domains and DNS Tunnelling**
   - High-entropy DNS names
   - Abnormal query lengths
   - Suspicious query/record-type patterns

4. **Malware in Encrypted Sessions**
   - TLS/QUIC metadata analysis
   - Fingerprint-based characteristics
   - Packet-size and timing behavior

5. **Reconnaissance and Port Scanning**
   - Source fan-out across destination ports
   - Source fan-out across destination hosts
   - Sequential or distributed scanning behavior

6. **Data Exfiltration**
   - Unusual flow-volume patterns
   - Asymmetric traffic behavior
   - Abnormal outbound/inbound byte relationships

These categories are deliberately handled within a **single common pipeline**, while individual detection components can use different statistical, machine-learning, or behavioral approaches depending on the threat.

---

# Proposed Solution

The proposed solution is a **modular passive threat-detection pipeline**.

Rather than building one monolithic model for every type of attack, the architecture separates the common network-processing stages from the threat-specific detection logic.

```text
                  PRODUCTION NETWORK
                         │
                         │
                  Gateway / Peering Link
                         │
                         ▼
                ┌───────────────────┐
                │ Passive Mirror /  │
                │    Data Diode      │
                └─────────┬─────────┘
                          │
                    ONE-WAY ONLY
                          │
                          ▼
                ┌───────────────────┐
                │ Traffic Ingestion │
                │  PCAP / Flow Data │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Preprocessing &   │
                │ Normalization     │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Feature Extraction│
                │ & Windowing       │
                └─────────┬─────────┘
                          │
              ┌───────────┼────────────┐
              │           │            │
              ▼           ▼            ▼
          ┌───────┐   ┌───────┐   ┌──────────┐
          │ DDoS  │   │  C2   │   │   DGA /  │
          │Detector│  │Detector│  │ DNS      │
          └───────┘   └───────┘   └──────────┘
              │           │            │
              ├───────────┼────────────┤
              │           │            │
              ▼           ▼            ▼
          ┌───────┐   ┌───────┐   ┌──────────┐
          │ Recon │   │Encrypted│  │Exfiltration│
          │Detector│  │ Traffic │  │ Detector │
          └───────┘   └───────┘   └──────────┘
              │
              └──────────────┬──────────────┘
                             ▼
                  ┌─────────────────────┐
                  │ Detection Fusion /  │
                  │ Scoring & Evidence  │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Standardized Alerts │
                  │ Timestamp            │
                  │ Flow ID              │
                  │ Threat Class         │
                  │ Confidence            │
                  │ Evidence              │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Security Dashboard  │
                  │ Live / Replay       │
                  └─────────────────────┘
```

The architecture follows the SIH requirement for a working prototype containing **ingestion, feature extraction, model inference, alert generation, and visualization**.

---

# How the Pipeline Works

## 1. Passive Traffic Ingestion

Traffic enters the monitoring environment through the one-way observation path.

The ingestion layer is strictly read-only. It can consume sources such as:

- Packet captures
- Flow records
- NetFlow
- IPFIX
- sFlow
- Derived network metadata

The system does not transmit traffic back toward the monitored network.

---

## 2. Preprocessing

Incoming traffic is converted into a consistent representation suitable for downstream analysis.

This stage handles tasks such as:

- parsing traffic/flow records,
- normalization,
- cleaning invalid records,
- temporal organization,
- grouping traffic into appropriate analysis windows, and
- preparing the observations for feature extraction.

The preprocessing layer is shared by the different threat detectors so that each model receives a consistent representation of the observed traffic.

---

## 3. Feature Extraction

The system does not depend on payload inspection.

Instead, it derives behavioral and statistical information from what is observable in the one-way traffic stream.

Depending on the threat, useful information can include:

- packet and byte rates,
- packet sizes,
- inter-arrival times,
- source/destination relationships,
- destination-port behavior,
- traffic volume,
- entropy,
- periodicity,
- flow asymmetry,
- protocol metadata,
- TLS/QUIC fingerprints,
- DNS characteristics,
- host/port fan-out.

This makes the architecture compatible with the fundamental passive-monitoring constraint.

For example, the reconnaissance detector can reason about a source contacting many destinations or ports without needing to actively probe those systems.

Research on flow-based port-scan detection similarly demonstrates that unidirectional flow information can be used to identify scanning behavior through characteristics such as flow size and variation.

---

# 4. Threat-Specific Detection

After feature extraction, the common feature stream is passed to the appropriate detection components.

Each detector is responsible for identifying a particular behavioral class.

The project therefore follows a **modular detection architecture**:

```text
                    Feature Stream
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
       DDoS Model      C2 Model        DNS Model
          │               │                │
          └───────────────┼────────────────┘
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
      Recon Model    Encrypted Model   Exfil Model
          │               │                │
          └───────────────┼────────────────┘
                          ▼
                  Detection Results
```

The important architectural property is that **the rest of the system does not need to know how an individual threat is detected**.

A detector can use statistical analysis, sequential detection, machine learning, behavioral analysis, or another suitable method as long as its output conforms to the common detection interface.

This also allows individual team members to develop and evaluate their respective detectors independently while integrating them into the same overall system.

---

# 5. Detection Fusion and Scoring

Individual detection components produce their observations and predictions.

These results are then converted into a common representation containing:

- threat category,
- confidence,
- severity,
- relevant flow/traffic information,
- supporting evidence.

The purpose of this layer is to turn model outputs into **security intelligence**, rather than exposing raw model predictions directly to the operator.

---

# 6. Alert Generation

The final output of the detection pipeline is a standardized alert.

The SIH specification requires structured alerts containing information such as:

```text
Timestamp
Flow Identifier
Threat Class
Confidence Score
Supporting Evidence
```

This allows different detectors to produce results that can be consumed consistently by the dashboard and other downstream components.

Example:

```json
{
  "timestamp": "...",
  "flow_id": "...",
  "threat_class": "RECONNAISSANCE",
  "confidence": 0.94,
  "severity": "HIGH",
  "evidence": {
    "unique_destination_ports": 47,
    "unique_destination_hosts": 31,
    "observation_window": "..."
  }
}
```

---

# 7. Visualization Dashboard

The dashboard provides the operator with a high-level view of detected threats.

It is intended to support both:

- **live/replay traffic analysis**, and
- investigation of generated alerts.

The dashboard presents information such as:

- detected threat type,
- severity,
- confidence,
- timestamp,
- affected flow/source information,
- supporting detection evidence.

The dashboard is therefore the final presentation layer of the pipeline rather than part of the detection logic itself.

---

# Core Architectural Principle

The entire system can be summarized as:

```text
OBSERVE
   ↓
REPRESENT
   ↓
EXTRACT FEATURES
   ↓
DETECT
   ↓
SCORE
   ↓
GENERATE INTELLIGENCE
   ↓
DISPLAY
```

There is deliberately **no reverse path**:

```text
                    ┌─────────────────────┐
                    │   Production       │
                    │     Network        │
                    └──────────┬──────────┘
                               │
                               │ traffic
                               ▼
                    ┌─────────────────────┐
                    │ Passive Monitoring  │
                    │      Enclave        │
                    └─────────────────────┘

                         NO RETURN PATH
                              ✕
```

This is the defining property of the project.

---

# Constraints

The system is designed under the following non-negotiable constraints.

## 1. Strictly One-Way / Read-Only Ingest

The monitoring environment receives traffic but cannot send traffic back.

Therefore:

- no active probing,
- no return connection,
- no mitigation command across the ingest path,
- no querying the original source,
- no querying the destination.

Any solution requiring a return path is outside the intended architecture.

---

## 2. No Payload Decryption

Encrypted traffic must remain encrypted.

For TLS/QUIC traffic, detection must rely on observable metadata and traffic behavior rather than decrypted payload contents.

Possible information includes fingerprints, packet sizes, timing sequences, and other metadata.

---

## 3. Passive Observation Only

The system can only reason from information that is actually visible at the monitoring point.

It must not assume access to information that would require communicating with the endpoints.

This is especially important when designing features: a feature is valid only if it can genuinely be derived from the observed traffic.

---

## 4. Streaming / Near Real-Time Processing

The system is not intended to simply process a dataset after the fact and produce an end-of-run report.

Traffic should be processed incrementally, allowing detections and alerts to be generated with bounded latency.

Offline datasets and PCAP replay can be used for development and demonstration, but the architecture must remain compatible with streaming operation.

---

## 5. Defined Throughput

The prototype must explicitly state the traffic rate at which it has been tested.

This may be expressed in terms such as:

- flows/second,
- packets/second, or
- Mbps/Gbps sustained.

The throughput target should therefore be treated as an engineering benchmark rather than an implicit assumption.

---

## 6. Standardized Output

Every detector must ultimately produce a common alert representation.

This prevents the dashboard and downstream components from becoming tightly coupled to individual models.

---

## 7. Observable Features Only

Features must be derived from the information available through the one-way monitoring interface.

A major implication is that conventional bidirectional-flow features cannot automatically be assumed to be valid.

For example, CICFlowMeter-style datasets commonly contain forward and backward flow statistics. A strict one-way interpretation requires retaining only features that can genuinely be derived from the observed direction. Our work therefore treats such datasets as sources of candidate features rather than automatically assuming that their complete biflow representation satisfies the SIH constraint.

---

# Data and Model Development

The project uses offline traffic datasets and replayed traffic during development and evaluation.

The development workflow is:

```text
Dataset / PCAP
      │
      ▼
Feature Validation
      │
      ▼
One-Way-Compatible Representation
      │
      ▼
Preprocessing
      │
      ▼
Feature Engineering
      │
      ▼
Model Training / Detector Development
      │
      ▼
Validation & Evaluation
      │
      ▼
Streaming Inference
      │
      ▼
Standardized Alerts
```

An important design rule is that **training features must correspond to features that can actually be obtained during deployment**.

This prevents a model from achieving high offline performance using information that would not be available in the real data-diode deployment.

---

# Research Foundation

The project builds on existing research into passive traffic analysis and network scanning.

Prior research has shown that passive, one-way traffic measurements can provide useful cyber-threat intelligence without requiring active interaction with network endpoints.

Research on port-scan detection has also explored flow-based and unidirectional approaches, including methods based on sequential hypothesis testing and traffic-flow characteristics.

These ideas inform the project's broader principle:

> **Malicious behavior can often be inferred from patterns in observed traffic, even when the detector cannot interact with the endpoints.**

---

# Project Goals

The overall system aims to provide:

- **Passive security monitoring**
- **One-way architecture compatibility**
- **Near-real-time threat detection**
- **Multiple threat-class detection**
- **Modular AI/ML detectors**
- **Explainable supporting evidence**
- **Standardized alerts**
- **Confidence and severity scoring**
- **Live/replay visualization**
- **Deployment suitability for isolated critical-infrastructure environments**

---

# What the System Does NOT Do

This project is intentionally **not**:

- an inline firewall,
- an active vulnerability scanner,
- an automated penetration-testing system,
- a packet-injection system,
- a mitigation system with a network return path,
- a payload-decryption system,
- or a conventional bidirectional IDS that assumes endpoint interaction.

Its role is **passive threat intelligence generation**.

The system observes the network, identifies suspicious behavior, and informs the operator.

---

# Repository Architecture

The implementation is organized around the following conceptual components:

```text
project/
│
├── ingestion/
│   └── Traffic / PCAP / Flow ingestion
│
├── preprocessing/
│   └── Cleaning, normalization, windowing
│
├── features/
│   └── Common and detector-specific features
│
├── detectors/
│   ├── ddos/
│   ├── botnet/
│   ├── dns/
│   ├── encrypted/
│   ├── reconnaissance/
│   └── exfiltration/
│
├── inference/
│   └── Model execution and scoring
│
├── alerts/
│   └── Standardized alert generation
│
├── dashboard/
│   └── Visualization
│
└── evaluation/
    └── Performance and throughput evaluation
```

The exact implementation can evolve, but the architectural separation should remain:

**ingestion → preprocessing → features → detection → scoring → alerts → dashboard**

---

# Summary

This project implements a **passive, one-way AI/ML threat-detection architecture for critical-infrastructure networks**.

Its key innovation is not simply the use of machine learning, but the requirement that the entire detection lifecycle operates under the constraints of a **data-diode-fed monitoring environment**.

The system therefore combines multiple specialized threat detectors behind a common streaming pipeline while enforcing the same fundamental rules across the project:

```text
                ONE-WAY TRAFFIC
                       │
                       ▼
              PASSIVE INGESTION
                       │
                       ▼
             FEATURE EXTRACTION
                       │
                       ▼
             THREAT DETECTION
                       │
                       ▼
              SCORING + EVIDENCE
                       │
                       ▼
              STANDARDIZED ALERT
                       │
                       ▼
                  DASHBOARD
```

The result is a security monitoring system that can provide actionable threat intelligence **without ever needing to communicate back with the monitored network**.