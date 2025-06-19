# EMB3D STIX CSV Builder 📦➡️📊

A lightweight **one-file** utility that converts the latest **MITRE EMB3D™ STIX bundle**  
into the familiar PID → TID → MID mapping CSV.

| Feature | Description |
|---------|-------------|
| 🔍 **Auto-discovers latest bundle** | Lists `assets/` on GitHub and fetches the highest `emb3d-stix-*.json`. |
| 🗜 **Single download, no scraping** | Entire knowledge base lives in one JSON → fewer network calls and fewer deps. |
| 📄 **13-column flat CSV** | Identical schema to the earlier scraper, so downstream tools keep working. |
| 🏷 **MIT‐style license** | Free to integrate into pipelines or dashboards. |

## Quick start

```bash
git clone https://github.com/Yeddo/EMB3D.git
cd EMB3D
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python build_emb3d_csv_from_stix.py           # → emb3d_mapping.csv
