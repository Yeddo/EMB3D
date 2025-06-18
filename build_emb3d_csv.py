#!/usr/bin/env python3
"""
Build a flattened CSV of the MITRE-EMB3D property-threat-mitigation mapping.

Requirements
------------
pip install requests beautifulsoup4 tqdm

Usage
-----
python build_emb3d_csv.py -o emb3d_mapping.csv
"""
from __future__ import annotations

import csv
import re
import time
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

RAW_BASE = "https://raw.githubusercontent.com/mitre/emb3d/main"
MAPPING_PATH = "_data/threats_properties_mitigations_mappings.json"
THREADS = 12                # tune for your bandwidth
RETRY  = 3                  # simple retry loop


def fetch(url: str) -> str:
    """HTTP GET with basic retry/back-off."""
    for attempt in range(1, RETRY + 1):
        r = requests.get(url, timeout=30)
        if r.ok:
            return r.text
        wait = 2 ** attempt
        tqdm.write(f"[warn] {url} -> {r.status_code}, retry {attempt}/{RETRY} in {wait}s")
        time.sleep(wait)
    r.raise_for_status()   # last error


# ---------- Threat helpers -------------------------------------------------

def parse_threat_html(html: str) -> dict[str, str]:
    """Return {description, poc, kew, cve, cwe} from a TID page."""
    soup = BeautifulSoup(html, "html.parser")
    get_section = lambda hdr: soup.find(id=re.compile(hdr, re.I))
    def list_texts(start_hdr: str) -> list[str]:
        hdr = get_section(start_hdr)
        if not hdr:
            return []
        ul = hdr.find_next("ul")
        return [li.get_text(" ", strip=True) for li in ul.find_all("li", recursive=False)] if ul else []

    desc_hdr = get_section("threat-description")
    description = desc_hdr.find_next("p").get_text(" ", strip=True) if desc_hdr else ""

    poc_links = list_texts("Proof of Concept")
    kew_links = list_texts("Known Exploitable Weakness")
    cve_links = list_texts(r"\bCVE\b")
    cwe_links = list_texts(r"\bCWE\b")

    return {
        "description": description,
        "poc": "; ".join(poc_links),
        "kew": "; ".join(kew_links),
        "cve": "; ".join(cve_links),
        "cwe": "; ".join(cwe_links),
    }

# ---------- Mitigation helpers ---------------------------------------------

def parse_mitigation_html(html: str) -> dict[str, str]:
    """Return {description, regs} from an MID page."""
    soup = BeautifulSoup(html, "html.parser")
    desc_hdr = soup.find(id=re.compile("^description$", re.I))
    description = desc_hdr.find_next("p").get_text(" ", strip=True) if desc_hdr else ""

    mapping_hdr = soup.find(id=re.compile("mappings?", re.I))
    regs = []
    if mapping_hdr:
        ul = mapping_hdr.find_next("ul")
        regs = [li.get_text(" ", strip=True) for li in ul.find_all("li", recursive=False)] if ul else []

    return {"description": description, "regs": "; ".join(regs)}

# ---------- Workers --------------------------------------------------------

def threat_worker(tid: str) -> dict[str, str]:
    url = f"{RAW_BASE}/threats/{tid}.html"
    return parse_threat_html(fetch(url))

def mitigation_worker(mid: str) -> dict[str, str]:
    url = f"{RAW_BASE}/mitigations/{mid}.html"
    return parse_mitigation_html(fetch(url))

# ---------- Main -----------------------------------------------------------

def build_csv(out_csv: Path) -> None:
    # 1. Pull master JSON map ------------------------------------------------
    mapping_json = requests.get(f"{RAW_BASE}/{MAPPING_PATH}", timeout=30).json()

    # 2. Kick off parallel pre-fetch of all threat + mitigation pages -------
    tids = {t["id"] for t in mapping_json["threats"]}
    mids = {m["id"] for t in mapping_json["threats"] for m in t["mitigations"]}

    tqdm.write(f"Fetching {len(tids)} threats & {len(mids)} mitigations …")
    with ThreadPoolExecutor(max_workers=THREADS) as exe:
        threat_futures = {exe.submit(threat_worker, tid): tid for tid in tids}
        mitigation_futures = {exe.submit(mitigation_worker, mid): mid for mid in mids}

        threat_info     = {tid: future.result()
                           for future, tid in tqdm(threat_futures.items(),
                                                   desc="Threats", total=len(tids))}
        mitigation_info = {mid: future.result()
                           for future, mid in tqdm(mitigation_futures.items(),
                                                   desc="Mitigations", total=len(mids))}

    # 3. Flatten to rows -----------------------------------------------------
    header = [
        "Property ID", "Property text",
        "Threat ID", "Threat text", "Threat Description",
        "Threat Proof of Concept", "Threat Known Exploitable Weakness",
        "CVE", "CWE",
        "Mitigation ID", "Mitigation Text", "Mitigation Level",
        "Mitigation Description", "Mitigation Regulatory Mapping"
    ]

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        writer.writeheader()

        for threat in mapping_json["threats"]:
            tid = threat["id"]
            t_extra = threat_info.get(tid, {})
            for prop in threat["properties"]:
                for mitig in threat["mitigations"]:
                    mid = mitig["id"]
                    m_extra = mitigation_info.get(mid, {})

                    row = {
                        "Property ID": prop["id"],
                        "Property text": prop["text"],

                        "Threat ID": tid,
                        "Threat text": threat["text"],
                        "Threat Description": t_extra.get("description", ""),
                        "Threat Proof of Concept": t_extra.get("poc", ""),
                        "Threat Known Exploitable Weakness": t_extra.get("kew", ""),
                        "CVE": t_extra.get("cve", ""),
                        "CWE": t_extra.get("cwe", ""),

                        "Mitigation ID": mid,
                        "Mitigation Text": mitig["text"],
                        "Mitigation Level": mitig["level"].capitalize(),

                        "Mitigation Description": m_extra.get("description", ""),
                        "Mitigation Regulatory Mapping": m_extra.get("regs", ""),
                    }
                    writer.writerow(row)

    tqdm.write(f"[ok] Wrote {out_csv} ({out_csv.stat().st_size/1024:.1f} KiB)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build MITRE-EMB3D mapping CSV")
    ap.add_argument("-o", "--output", default="emb3d_mapping.csv",
                    type=Path, help="CSV file to write (default: emb3d_mapping.csv)")
    args = ap.parse_args()
    build_csv(args.output)
