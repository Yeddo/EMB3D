#!/usr/bin/env python3
"""
MITRE EMB3D CSV Builder
Author      : Jason Bisnette
Created     : March 2025
Last Updated: June 2025

Purpose
-------
Rebuild the EMB3D mapping spreadsheet whenever MITRE publishes an update.

    • Downloads the canonical JSON mapping from the EMB3D GitHub repository
    • Scrapes every Threat (TID-###) and Mitigation (MID-###) page to collect
      descriptions, Proof-of-Concept links, CVEs, CWEs, and regulatory mappings
    • Produces a flat, analysis-ready CSV with one row per PID × TID × MID

Usage
-----
    python3 build_emb3d_csv.py                # → emb3d_mapping.csv
    python3 build_emb3d_csv.py -o my.csv      # custom output name

Dependencies
------------
    • requests
    • beautifulsoup4
    • tqdm

License
-------
This script is released under the MIT License.
MITRE EMB3D™ content is © MITRE and used under its Terms of Use.
"""

# ────────────────────────────────────────────────────────────────────────────────
# Standard-library imports
# ────────────────────────────────────────────────────────────────────────────────
import csv                                 # CSV file generation
import re                                  # Regular-expression helpers
import time                                # Sleep for exponential back-off
import argparse                            # Parse command-line flags
from pathlib import Path                   # Filesystem-safe path objects
from concurrent.futures import ThreadPoolExecutor   # Parallel web requests

# ────────────────────────────────────────────────────────────────────────────────
# Third-party imports
# ────────────────────────────────────────────────────────────────────────────────
import requests                            # HTTP/HTTPS client
from bs4 import BeautifulSoup              # HTML parsing
from tqdm import tqdm                      # Progress bars

# ────────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────────
RAW_BASE     = "https://raw.githubusercontent.com/mitre/emb3d/main"  # GitHub raw content
MAPPING_PATH = "_data/threats_properties_mitigations_mappings.json"  # JSON map in repo
THREADS      = 12                               # ThreadPool parallelism
RETRY        = 3                                # Max HTTP retry attempts

# ────────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────────────────────────
def fetch(url: str) -> str:
    """Return text of *url* with exponential back-off + retry."""
    for attempt in range(1, RETRY + 1):          # Try up to RETRY times
        r = requests.get(url, timeout=30)        # Issue GET request
        if r.ok:                                 # Success → return body
            return r.text
        wait = 2 ** attempt                      # Exponential back-off seconds
        tqdm.write(f"[warn] {url} -> {r.status_code}  (retry {attempt}/{RETRY} in {wait}s)")
        time.sleep(wait)                         # Sleep before next attempt
    r.raise_for_status()                         # All retries failed → raise

def extract_ids(lines: list[str], pattern: str) -> list[str]:
    """Return list of regex *pattern* matches (e.g., CVE-IDs) from lines."""
    rx = re.compile(pattern)                     # Compile regex once
    return [m.group(0) for txt in lines if (m := rx.search(txt))]  # Keep matches only

def li_to_text(li) -> str:
    """Convert <li> to 'Link Text (URL)' or plain text when no anchor."""
    a = li.find("a", href=True)                  # Find first hyperlink
    if a:                                        # If hyperlink exists
        return f"{a.get_text(' ', strip=True)} ({a['href']})"  # Return combined string
    return li.get_text(" ", strip=True)          # Else return raw text

# ────────────────────────────────────────────────────────────────────────────────
# Threat-page Parser
# ────────────────────────────────────────────────────────────────────────────────
def parse_threat_html(html: str) -> dict[str, str]:
    """Extract description, PoC, CVE, CWE from a Threat HTML page."""
    soup = BeautifulSoup(html, "html.parser")    # Parse HTML to tree

    # Inner helper: find heading by id (handles hyphen/underscore/space variants)
    def find_hdr(keywords: str):
        regex = re.compile(keywords, re.I)       # Case-insensitive pattern
        return soup.find(lambda tag: tag.has_attr("id") and regex.search(tag["id"]))

    # Inner helper: return list items under heading that matches *id_regex*
    def list_under(id_regex: str) -> list[str]:
        hdr = find_hdr(id_regex)                 # Locate heading node
        if not hdr:                              # If not found → return empty
            return []
        ul = hdr.find_next("ul")                 # Next <ul> after heading
        return [li_to_text(li)                   # Convert each <li> to text/URL
                for li in ul.find_all("li", recursive=False)] if ul else []

    desc_hdr    = find_hdr(r"threat[-_ ]?description")   # "Threat Description" heading
    description = desc_hdr.find_next("p").get_text(" ", strip=True) if desc_hdr else ""

    poc_lines = list_under(r"proof[-_ ]?of[-_ ]?concept")  # PoC bullet list
    cve_lines = list_under(r"\bcve\b")                    # CVE bullet list
    cwe_lines = list_under(r"\bcwe\b")                    # CWE bullet list

    return {                                   # Assemble dict for caller
        "description": description,
        "poc": "; ".join(poc_lines),           # Join PoC entries with semicolon
        "cve": "; ".join(extract_ids(cve_lines, r"CVE-\d{4}-\d{4,7}")),
        "cwe": "; ".join(extract_ids(cwe_lines, r"CWE-\d+")),
    }

# ────────────────────────────────────────────────────────────────────────────────
# Mitigation-page Parser
# ────────────────────────────────────────────────────────────────────────────────
def parse_mitigation_html(html: str) -> dict[str, str]:
    """Extract description + regulatory mappings from Mitigation HTML."""
    soup = BeautifulSoup(html, "html.parser")    # Parse HTML

    desc_hdr = soup.find(id=re.compile("^description$", re.I))  # Heading id="description"
    description = desc_hdr.find_next("p").get_text(" ", strip=True) if desc_hdr else ""

    map_hdr = soup.find(id=re.compile("mappings?", re.I))   # Heading "Mappings"
    regs = []                                               # List of regulatory refs
    if map_hdr:                                             # If section exists
        ul = map_hdr.find_next("ul")                        # Next <ul>
        regs = [li.get_text(" ", strip=True)                # Plain text bullets
                for li in ul.find_all("li", recursive=False)] if ul else []

    return {                               # Return dict to caller
        "description": description,
        "regs": "; ".join(regs),
    }

# ────────────────────────────────────────────────────────────────────────────────
# Thin wrappers for ThreadPool call-sites
# ────────────────────────────────────────────────────────────────────────────────
def threat_worker(tid: str) -> dict[str, str]:
    """Download + parse a single Threat page."""
    return parse_threat_html(fetch(f"{RAW_BASE}/threats/{tid}.html"))

def mitigation_worker(mid: str) -> dict[str, str]:
    """Download + parse a single Mitigation page."""
    return parse_mitigation_html(fetch(f"{RAW_BASE}/mitigations/{mid}.html"))

# ────────────────────────────────────────────────────────────────────────────────
# Main driver
# ────────────────────────────────────────────────────────────────────────────────
def build_csv(out_csv: Path) -> None:
    """High-level workflow: download JSON, scrape pages, write CSV."""
    mapping_json = requests.get(f"{RAW_BASE}/{MAPPING_PATH}", timeout=30).json()  # Load master JSON

    # Build PID→text fallback for properties missing 'text' field
    property_lookup = {p["id"]: p["text"]
                       for t in mapping_json["threats"]
                       for p in t["properties"]
                       if "text" in p}

    # Unique TIDs and MIDs for one-time page fetch
    tids = {t["id"] for t in mapping_json["threats"]}
    mids = {m["id"] for t in mapping_json["threats"] for m in t["mitigations"]}

    tqdm.write(f"Fetching {len(tids)} threats & {len(mids)} mitigations …")

    # Parallel download + parse using ThreadPool
    with ThreadPoolExecutor(max_workers=THREADS) as exe:
        threat_info = {tid: fut.result()                     # Map TID→info
                       for fut, tid in tqdm(
                           {exe.submit(threat_worker, tid): tid for tid in tids}.items(),
                           desc="Threats", total=len(tids))}

        mitig_info  = {mid: fut.result()                     # Map MID→info
                       for fut, mid in tqdm(
                           {exe.submit(mitigation_worker, mid): mid for mid in mids}.items(),
                           desc="Mitigations", total=len(mids))}

    # CSV header definition
    header = [
        "Property ID", "Property text",
        "Threat ID", "Threat text", "Threat Description",
        "Threat Proof of Concept", "CVE", "CWE",
        "Mitigation ID", "Mitigation Text", "Mitigation Level",
        "Mitigation Description", "Mitigation Regulatory Mapping"
    ]

    # Open destination file for writing
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)  # CSV writer w/header order
        writer.writeheader()                            # Emit header row

        # Walk nested JSON structure to flatten into rows
        for threat in mapping_json["threats"]:          # Loop over each threat block
            tid     = threat["id"]                      # Current Threat ID
            t_extra = threat_info.get(tid, {})          # Scraped threat metadata

            for prop in threat["properties"]:           # Loop each property for threat
                pid       = prop["id"]                  # Property ID
                prop_text = prop.get("text") or property_lookup.get(pid, "")  # Reliable text

                for mitig in threat["mitigations"]:     # Loop each linked mitigation
                    mid      = mitig["id"]              # Mitigation ID
                    m_extra  = mitig_info.get(mid, {})  # Scraped mitigation metadata

                    # Write flattened CSV row
                    writer.writerow({
                        "Property ID":   pid,
                        "Property text": prop_text,
                        "Threat ID":     tid,
                        "Threat text":   threat["text"],
                        "Threat Description":     t_extra.get("description", ""),
                        "Threat Proof of Concept": t_extra.get("poc", ""),
                        "CVE":                    t_extra.get("cve", ""),
                        "CWE":                    t_extra.get("cwe", ""),
                        "Mitigation ID":   mid,
                        "Mitigation Text": mitig["text"],
                        "Mitigation Level": mitig["level"].capitalize(),
                        "Mitigation Description":        m_extra.get("description", ""),
                        "Mitigation Regulatory Mapping": m_extra.get("regs", ""),
                    })

    tqdm.write(f"[ok] Wrote {out_csv} ({out_csv.stat().st_size/1024:.1f} KiB)")

# ────────────────────────────────────────────────────────────────────────────────
# CLI Entry-point
# ────────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build MITRE-EMB3D mapping CSV")  # Argument parser
    ap.add_argument("-o", "--output", default="emb3d_mapping.csv",             # Output path flag
                    type=Path, help="CSV file to write (default: emb3d_mapping.csv)")
    build_csv(ap.parse_args().output)                                          # Delegate to main workflow
