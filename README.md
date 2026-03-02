# AI-Powered Multi-Agent Cybersecurity Threat Intelligence Pipeline

## Overview
This project is a modular cybersecurity threat intelligence pipeline that combines deterministic detection logic with large language model (LLM) reasoning to analyze system logs, enrich vulnerabilities, map adversary behavior, and generate executive-ready incident reports.

The system integrates real-world security data sources (NVD CVE database and MITRE ATT&CK framework) and produces both human-readable and machine-readable outputs.

---

## Architecture

Logs  
→ Rule-Based Detection Engine  
→ LLM Log Classification  
→ CVE Enrichment (NVD API)  
→ MITRE ATT&CK Mapping  
→ CVSS-Weighted Risk Scoring  
→ Executive Report (TXT + JSON)

---

## Core Capabilities

### 1. Hybrid Detection Engine
- Rule-based detection for brute force, SQL injection, and port scanning
- LLM-based contextual log interpretation
- Extracts services, attack types, and indicators

### 2. Vulnerability Intelligence (NVD Integration)
- Real-time CVE lookups using NVD REST API
- Extracts CVSS v3.1 / v3.0 / v2 base scores
- Structured vulnerability output for downstream analysis

### 3. MITRE ATT&CK Mapping
- Maps detected activity to tactics and techniques
- Generates direct ATT&CK framework references
- Aligns incident findings with adversary behaviors

### 4. Risk Scoring Engine
- Computes weighted severity score from CVSS data
- Categorizes risk as Critical / High / Medium / Low
- Provides deterministic risk baseline for reporting

### 5. Reporting & Artifacts
- Executive-level incident report (TXT)
- Structured JSON artifact for SOC/automation workflows
- CLI-based execution for flexible log input

--- 

## Technologies Used
- Python
- Groq LLM (Llama 3.3 70B)
- NVD CVE REST API
- MITRE ATT&CK Framework
- JSON data modeling
- Modular agent-based architecture

---

## Example Usage 

```bash
py main.py sample_logs.txt