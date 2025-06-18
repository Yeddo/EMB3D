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
from concurrent.futures import ThreadPoolExecutor

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

RAW_BASE = "https://raw.githubusercontent.com/mitre/emb3d/main"
MAPPING_PATH = "_data/threats_properties_mitigations_mappings.json"
THREADS = 12
RETRY   = 3


# --------------------------------------------------------------------------- #
#                               helper functions                              #
# --------------------------------------------------------------------------- #
def fetch(url: str) -> str:
    """HTTP GET with simple exponential back-off retry."""
    for attempt in range(1, RETRY + 1):
        r = requests.get(url, timeout=30)
        if r.ok:
            return r.text
        wait = 2 ** attempt
        tqdm.write(f"[warn] {url} -> {r.status_code}  (retry {attempt}/{RETRY} in {wait}s)")
        time.sleep(wait)
    r.raise_for_status()           # propagate last error


def extract_ids(lines: list[str], pattern: str) -> list[str]:
    """Return the first regex match from each line (if any)."""
    rx = re.compile(pattern)
    ids = []
    for txt in lines:
        m = rx.search(txt)
        if m:
            ids.append(m.group(0))
    return ids


# ----------------------------- threat page parser --------------------------- #
def parse_threat_html(html: str) -> dict[str, str]:
    soup = BeautifulSoup(html, "html.parser")

    def hdr(name):               # locate an <h2 id="..."> by loose pattern
        return soup.find(id=re.compile(name, re.I))

    def list_under(h2_pattern: str) -> list[str]:
        h = hdr(h2_pattern)
        if not h:
            return []
        ul = h.find_next("ul")
        return [li.get_text(" ", strip=True)
                for li in ul.find_all("li", recursive=False)] if ul else []

    desc_hdr = hdr("threat-description")
    description = desc_hdr.find_next("p").get_text(" ", strip=True) if desc_hdr else ""

    poc_lines  = list_under("Proof of Concept")

    cve_lines  = list_under(r"\bCVE\b")
    cwe_lines  = list_under(r"\bCWE\b")

    return {
        "description": description,
        "poc": "; ".join(poc_lines),

        # identifiers only
        "cve": "; ".join(extract_ids(cve_lines, r"CVE-\d{4}-\d{4,7}")),
        "cwe": "; ".join(extract_ids(cwe_lines, r"CWE-\d+")),
    }


# --------------------------- mitigation page parser ------------------------- #
def parse_mitigation_html(html: str) -> dict[str, str]:
    soup = BeautifulSoup(html, "html.parser")

    desc_hdr = soup.find(id=re.compile("^description$", re.I))
    description = desc_hdr.find_next("p").get_text(" ", strip=True) if desc_hdr else ""

    map_hdr = soup.find(id=re.compile("mappings?", re.I))
    regs = []
    if map_hdr:
        ul = map_hdr.find_next("ul")
        regs = [li.get_text(" ", strip=True)
                for li in ul.find_all("li", recursive=False)] if ul else []

    return {"description": description, "regs": "; ".join(regs)}


# ------------------------------ worker wrappers ---------------------------- #
def threat_worker(tid: str) -> dict[str, str]:
    return parse_threat_html(fetch(f"{RAW_BASE}/threats/{tid}.html"))


def mitigation_worker(mid: str) -> dict[str, str]:
    return parse_mitigation_html(fetch(f"{RAW_BASE}/mitigations/{mid}.html"))


# ---------------------------------- main ----------------------------------- #
def build_csv(out_csv: Path) -> None:
    mapping_json = requests.get(f"{RAW_BASE}/{MAPPING_PATH}", timeout=30).json()

    # PID text lookup for rows where `"text"` is missing
    property_lookup = {
        p["id"]: p["text"]
        for t in mapping_json["threats"]
        for p in t["properties"]
        if "text" in p
    }

    tids = {t["id"] for t in mapping_json["threats"]}
    mids = {m["id"] for t in mapping_json["threats"] for m in t["mitigations"]}

    tqdm.write(f"Fetching {len(tids)} threats & {len(mids)} mitigations …")

    with ThreadPoolExecutor(max_workers=THREADS) as exe:
        threat_info = {tid: fut.result()
                       for fut, tid in tqdm(
                           {exe.submit(threat_worker, tid): tid for tid in tids}.items(),
                           desc="Threats", total=len(tids))}

        mitig_info  = {mid: fut.result()
                       for fut, mid in tqdm(
                           {exe.submit(mitigation_worker, mid): mid for mid in mids}.items(),
                           desc="Mitigations", total=len(mids))}

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
            poc_val = t_extra.get("poc", "")              # single source for PoC

            for prop in threat["properties"]:
                prop_id   = prop["id"]
                prop_text = prop.get("text") or property_lookup.get(prop_id, "")

                for mitig in threat["mitigations"]:
                    mid = mitig["id"]
                    m_extra = mitig_info.get(mid, {})

                    writer.writerow({
                        "Property ID":   prop_id,
                        "Property text": prop_text,

                        "Threat ID":     tid,
                        "Threat text":   threat["text"],
                        "Threat Description":               t_extra.get("description", ""),
                        "Threat Proof of Concept":          poc_val,
                        "Threat Known Exploitable Weakness": poc_val,   # per new requirement
                        "CVE":                              t_extra.get("cve", ""),
                        "CWE":                              t_extra.get("cwe", ""),

                        "Mitigation ID":   mid,
                        "Mitigation Text": mitig["text"],
                        "Mitigation Level": mitig["level"].capitalize(),

                        "Mitigation Description":          m_extra.get("description", ""),
                        "Mitigation Regulatory Mapping":   m_extra.get("regs", ""),
                    })

    tqdm.write(f"[ok] Wrote {out_csv} ({out_csv.stat().st_size/1024:.1f} KiB)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build MITRE-EMB3D mapping CSV")
    ap.add_argument("-o", "--output", default="emb3d_mapping.csv",
                    type=Path, help="CSV file to write (default: emb3d_mapping.csv)")
    args = ap.parse_args()
    build_csv(args.output)
