# EMB3D STIX CSV Builder

Fetches the latest MITRE EMB3D™ STIX bundle and flattens it into a PID → TID → MID CSV.

## Features

- **Auto-discover & download** the newest `emb3d-stix-*.json` via GitHub API  
- **No HTML scraping** — all data from STIX properties & relationships  
- **Identical 13-column schema** for seamless downstream use  

## Quick Start

```bash
git clone https://github.com/Yeddo/EMB3D.git
cd EMB3D
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python build_emb3d_csv_from_stix.py           # → emb3d_mapping.csv

Command-line options

    -o, --output : set custom CSV filename (default: emb3d_mapping.csv)

CSV Columns

    Property ID
    Property text
    Threat ID
    Threat text
    Threat Description
    Threat Proof of Concept
    CVE
    CWE
    Mitigation ID
    Mitigation Text
    Mitigation Level
    Mitigation Description
    Mitigation Regulatory Mapping

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

[![CSV build](https://github.com/Yeddo/EMB3D/actions/workflows/ci.yml/badge.svg)](https://github.com/Yeddo/EMB3D/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Yeddo/EMB3D?logo=github)](https://github.com/Yeddo/EMB3D/releases)

License: MIT
Data: MITRE EMB3D™ © MITRE under its Terms of Use