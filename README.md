### 📌 MITRE EMB3D JSON Parser

**Author:** Jason Bisnette  
**Date:** March 2025  

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 📖 Overview
This script extracts, processes, and formats MITRE EMB3D JSON data into an Excel file.
It is used to rebuild the **MITRE EMB3D mapping spreadsheet** when updates are released.

### 🔹 Features
✔ **Extracts & Maps Data**:
- **Properties (PID)** → **Threats (TID)**
- **Threats (TID)** → **Mitigations (MID)**  
✔ **Handles JSON data from either local files or GitHub.**  
✔ **Optional Excel formatting (`-Format` flag).**  
✔ **Automatically installs missing dependencies.**  

---

## 🚀 Installation

### **1️⃣ Clone the Repository**
git clone https://github.com/YOUR_GITHUB_USERNAME/emb3d-json-parser.git
cd emb3d-json-parser

🔧 Dependencies (The script will auto-install missing dependencies if needed.)

The script requires:

    pandas → Handles structured data.
    requests → Fetches JSON from MITRE's GitHub.
    openpyxl → Writes and formats Excel files.

Install Dependencies Manually:

pip install pandas requests openpyxl

or

pip install -r requirements.txt

🛠 Usage
Run the Script
📌 Option 1: Use Local JSON Files (download them yourself) (You will be prompted to enter the file paths for threats.json, mitigations.json, and properties.json.)

python3 emb3d_jsonParser.py

📌 Option 2: Download JSON directly from MITRE EMB3D's GitHub

python3 emb3d_jsonParser.py

📌 Option 3: Apply Excel Formatting (bold headers, cell merging of adjacent duplicates for readability, column resizing, and some centering of text).

python3 emb3d_jsonParser.py -Format

## 📊 Example Output (Excel File)
+----------------------+-------------------------+---------------------+------------------------+------------------------+-------------------------+
| Property ID (PID)    | Property Description    | Threat ID (TID)     | Threat Description     | Mitigation ID (MID)    | Mitigation Description  |
+----------------------+-------------------------+---------------------+------------------------+------------------------+-------------------------+
| PID-001             | Property 1 Description  | TID-001             | Threat 1 Description   | MID-001                | Mitigation 1 Description|
|-------------------------------------------------------------------------------------------------------------------------------------------------|
| PID-002             | Property 2 Description  | TID-002             | Threat 2 Description   | MID-002                | Mitigation 2 Description|
+----------------------+-------------------------+---------------------+------------------------+------------------------+-------------------------+

📂 Directory Structure

📂 emb3d-json-parser
│── emb3d_jsonParser.py      # Main script
│── requirements.txt         # List of dependencies
│── README.md                # Documentation

📜 License

This project is licensed under the MIT License.
