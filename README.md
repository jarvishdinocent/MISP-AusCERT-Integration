# MISP-AusCERT-Integration 🛡️🇦🇺

![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![MISP](https://img.shields.io/badge/MISP-Integration-red.svg?style=for-the-badge)
![Security](https://img.shields.io/badge/SOC-Automation-green.svg?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-important.svg?style=for-the-badge)

**An automated Cyber Threat Intelligence (CTI) pipeline that converts unstructured AusCERT advisories into actionable MISP events.**

---

## 📖 Overview

The **MISP-AusCERT-Integration** tool is designed for security analysts and SOC teams who need to ingest regional threat data without the manual overhead. It scrapes the latest advisories from **AusCERT (Australia CERT)**, extracts high-fidelity Indicators of Compromise (IOCs), calculates a dynamic threat score, and populates your MISP instance.

### Why this exists?
Manual extraction of IOCs from advisory PDFs or web pages is slow and prone to error. This pipeline ensures that regional threats—specifically those impacting the Australian landscape—are identified and synchronized to your defensive stack in minutes, not hours.

---

## ✨ Key Features

*   **🔍 Multi-Vector Extraction:** Advanced regex patterns for:
    *   **Network:** IPv4 addresses and Fully Qualified Domain Names (FQDNs).
    *   **Files:** MD5, SHA1, and SHA256 hashes.
*   **🧠 Intelligent Scoring:** Automatically assigns a `Threat Score` based on advisory sentiment (e.g., *Ransomware* or *Critical* keywords).
*   **🛡️ Active Deduplication:** Real-time API checks against your MISP instance to prevent duplicate attributes and maintain a clean database.
*   **🏷️ Automated Enrichment:** Applies global standards including `TLP:WHITE`, `osint`, and `country:AU`.
*   **🔗 Source Traceability:** Every IOC includes a comment pointing back to the specific AusCERT advisory URL for rapid pivoting.

---

## 🏗️ Technical Workflow

1.  **Ingestion:** Fetches HTML data from the AusCERT advisory portal.
2.  **Parsing:** Beautiful Soup extracts the core text content.
3.  **Extraction:** Regex engine identifies IPs, Domains, and Hashes.
4.  **Verification:** The script queries the MISP controller to see if the IOC already exists.
5.  **Creation:** New events are generated with appropriate threat levels and tags.

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/jarvishdinocent/MISP-AusCERT-Integration.git
cd MISP-AusCERT-Integration

# Create virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
.\venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
