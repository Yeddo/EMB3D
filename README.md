# EMB3D CSV Builder

*Flatten the entire MITRE EMB3D™ property → threat → mitigation knowledge base into a clean, analysis-ready CSV.*

[![Latest release](https://img.shields.io/github/v/release/Yeddo/EMB3D?logo=github)](https://github.com/Yeddo/EMB3D/releases)
![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## ✨ What it does
* **Downloads** the authoritative mapping file  
  `_data/threats_properties_mitigations_mappings.json` from the MITRE EMB3D GitHub repo.
* **Scrapes** every threat (`TID-###`) and mitigation (`MID-###`) web page to pull  
  * threat description, PoC / Known-Exploit links, CVEs, CWEs  
  * mitigation description and IEC 62443-4-2 (or other) regulatory mappings
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
  pip install requests beautifulsoup4 tqdm
