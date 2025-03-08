MITRE EMB3D JSON Parser

Author: Jason Bisnette
Date: March 2025

Overview

This script is designed to extract, process, and format MITRE's EMB3D JSON data into a structured Excel spreadsheet.
It helps rebuild the MITRE EMB3D mapping spreadsheet when MITRE releases updates.
Features

✔ Extracts & Maps Data:

    Properties (PID) → Threats (TID)
    Threats (TID) → Mitigations (MID)
    ✔ Handles JSON data from either local files or GitHub.
    ✔ Optional Excel formatting for readability (-Format flag).
    ✔ Automatically installs missing dependencies.

Installation
1️⃣ Clone the Repository

git clone https://github.com/YOUR_GITHUB_USERNAME/emb3d-json-parser.git
cd emb3d-json-parser

2️⃣ Install Dependencies

Ensure you have Python 3.x installed, then run:

pip install -r requirements.txt

(The script will automatically install missing dependencies if needed.)
Usage
Basic Execution (Use Local JSON Files)

python3 emb3d_jsonParser.py

    The script will prompt you for the paths to:
        threats.json
        mitigations.json
        properties.json

Auto-Download JSON from GitHub

python3 emb3d_jsonParser.py

    Choose option 2 when prompted, and the script will fetch the latest JSON from MITRE's GitHub.

Enable Excel Formatting

python3 emb3d_jsonParser.py -Format

    The script will process the data and apply formatting to the Excel file.

Example Output

After running the script, an Excel file (emb3d_mapping.xlsx) is generated with the following structure:
Property ID (PID)	Property Description	Threat ID (TID)	Threat Description	Mitigation ID (MID)	Mitigation Description
PID-001	Property 1 Description	TID-001	Threat 1 Description	MID-001	Mitigation 1 Description
PID-002	Property 2 Description	TID-002	Threat 2 Description	MID-002	Mitigation 2 Description
Dependencies

The script requires the following Python libraries:

    pandas → Handles data in a structured format.
    requests → Fetches JSON data from MITRE's GitHub.
    openpyxl → Writes and formats Excel files.

Manually Install Dependencies (If Needed)

pip install pandas requests openpyxl

How It Works
1️⃣ Fetch JSON Data

The script loads JSON files from either:

    GitHub (MITRE EMB3D public repo)
    Local JSON files (user-provided)

2️⃣ Parse & Process Data

    Extracts Property IDs (PIDs)
    Extracts Threat IDs (TIDs)
    Extracts Mitigation IDs (MIDs)
    Maps PIDs → TIDs and TIDs → MIDs

3️⃣ Export Data to Excel

    Saves the processed data as emb3d_mapping.xlsx.
    Optionally applies formatting (bold headers, column auto-sizing, and merged cells).

Code Structure

📂 emb3d-json-parser
│── emb3d_jsonParser.py      # Main script
│── requirements.txt         # List of dependencies
│── README.md                # Documentation

Contributing

Feel free to submit issues or pull requests to improve the script.
For major changes, please open an issue first to discuss the proposal.
License

This project is licensed under the MIT License.
