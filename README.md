
# EMB3D CSV Builder

*Flatten the entire MITRE EMB3D™ property → threat → mitigation knowledge base into a clean, analysis-ready CSV.*

[![Latest release](https://img.shields.io/github/v/release/Yeddo/EMB3D?logo=github)](https://github.com/Yeddo/EMB3D/releases)
![Python](https://img.shields.io/badge/Python-3.x-blue.svg) 
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## ✨ What it does
* **Downloads** the authoritative mapping file   
  `emb3d-stix*.json` from the MITRE EMB3D GitHub repo (https://github.com/mitre/emb3d/tree/main/assets).
* **Scrapes** STIX .jason to pull threat description, PoC / Known-Exploit links, CVEs, CWEs,  
  * mitigation description and regulatory mappings.
* **Produces one CSV row per `PID -> TID -> MID`** with a fixed 14-column schema.

---

## Column layout

| # | Column | Notes |
|---|--------|-------|
| 1 | `Property ID` | `PID-###` |
| 2 | `Property text` | human-readable label |
| 3 | `Threat ID` | `TID-###` |
| 4 | `Threat text` | headline |
| 5 | `Threat Description` | first paragraph on threat page |
| 6 | `Threat Proof of Concept` | PoC links (`;`-separated) |
| 7 | `CVE` | identifiers only (`CVE-YYYY-NNNN…`) |
| 8 | `CWE` | identifiers only (`CWE-####`) |
| 9 | `Mitigation ID` | `MID-###` |
|10 | `Mitigation Text` | headline |
|11 | `Mitigation Level` | Foundational / Intermediate / Leading |
|12 | `Mitigation Description` | first paragraph on mitigation page |
|13 | `Mitigation Regulatory Mapping` | e.g. “IEC 62443 4-2 EDR 3.14” |

---

## 🔧 Requirements

* Python 3.9 +  
* Packages:  
  ```bash
  pip install requests 

# EMB3D STIX CSV Builder

Fetches the latest MITRE EMB3D™ STIX bundle and flattens it into a PID → TID → MID CSV.

## Features

- **Auto-discover & download** the newest `emb3d-stix-*.json` via GitHub API  
- **All data from STIX properties & relationships    

## Quick Start

```bash
git clone https://github.com/Yeddo/EMB3D.git
cd EMB3D
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python build_emb3d_csv_from_stix.py           # → emb3d_mapping.csv

Command-line options

    -o, --output : set custom CSV filename (default: emb3d_mapping.csv)

(Optional) GitHub Actions
name: Build EMB3D CSV
on:
  push:
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python build_emb3d_csv_from_stix.py
      - name: Commit & push
        run: |
          git config user.name  "emb3d-bot"
          git config user.email "emb3d-bot@example.com"
          git add emb3d_mapping.csv
          git commit -m "chore: update CSV" || echo "No changes"
          git push

License: MIT
Data: MITRE EMB3D™ © MITRE under its Terms of Use
