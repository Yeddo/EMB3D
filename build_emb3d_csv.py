#!/usr/bin/env python3
"""
MITRE EMB3D CSV Builder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Uses a MITRE's STIX file from the public GitHub
repository and flattens it into one row per PID→TID→MID CSV that the
scraper produced.

Key design points
-----------------
* **Every datum comes from the STIX bundle itself.
* **Auto discovers the newest STIX file** in `https://github.com/mitre/emb3d/tree/main/assets/` (version aware).
* **Zero external deps** beyond the Python 3 standard library (✧ optional packaging for nicer version sorting - falls back to lexical order).

Usage
-----
    python3 build_emb3d_csv_from_stix.py                # emb3d_mapping.csv
    python3 build_emb3d_csv_from_stix.py -o out.csv     # custom output name

The generated CSV header ....
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import urllib.request as urlreq
from urllib.error import HTTPError, URLError

# -----------------------------------------------------------------------------
# Constants & simple helpers
# -----------------------------------------------------------------------------
ASSETS_API = "https://api.github.com/repos/mitre/emb3d/contents/assets"
RAW_BASE   = "https://raw.githubusercontent.com/mitre/emb3d/main/assets"

SEMVER_RX  = re.compile(r"(\d+\.\d+\.\d+)")


def latest_stix_info() -> Tuple[str, str]:
    """Return *(filename, download_url)* of the newest STIX JSON in /assets."""
    with urlreq.urlopen(ASSETS_API, timeout=30) as resp:
        entries = json.load(resp)

    stix_files: List[Tuple[str, str]] = [
        (e["name"], e["download_url"]) for e in entries
        if e["name"].startswith("emb3d-stix") and e["name"].endswith(".json")
    ]
    if not stix_files:
        sys.exit("[fatal] No STIX files found under assets/ – repo layout changed?")

    # Sort descending by semantic version if possible, else by name.
    try:
        from packaging.version import Version  # pylint: disable=import-error
        stix_files.sort(key=lambda t: Version(SEMVER_RX.search(t[0]).group(1)), reverse=True)
    except Exception:
        stix_files.sort(reverse=True)

    return stix_files[0]


# -----------------------------------------------------------------------------
# STIX parsing logic (standard‑library only)
# -----------------------------------------------------------------------------

def load_stix_bundle(url: str) -> Dict:
    """Download & parse the STIX bundle at *url*."""
    try:
        with urlreq.urlopen(url, timeout=60) as resp:
            return json.load(resp)
    except (HTTPError, URLError) as err:
        sys.exit(f"[fatal] Unable to fetch STIX bundle – {err}")


def split_objects(objects: List[Dict]) -> Tuple[Dict, Dict, List]:
    """Return dicts keyed by id for vulnerabilities(TID), mitigations(MID) and
    the raw relationship list."""
    vulns = {o["id"]: o for o in objects if o["type"] == "vulnerability"}
    mitigs = {o["id"]: o for o in objects if o["type"] == "course-of-action"}
    rels  = [o for o in objects if o["type"] == "relationship"]
    return vulns, mitigs, rels


def build_lookup(objects: Dict, field: str) -> Dict[str, str]:
    """Utility: make {id: obj[field]} with default ''."""
    return {oid: o.get(field, "") for oid, o in objects.items()}


# -----------------------------------------------------------------------------
# CSV generation
# -----------------------------------------------------------------------------

def write_csv(path: Path, bundle: Dict) -> None:
    vulns, mitigs, rels = split_objects(bundle["objects"])

    # Build quick‑access look‑ups for the x_mitre custom fields.
    t_desc = build_lookup(vulns, "description")
    t_poc  = build_lookup(vulns, "x_mitre_emb3d_threat_evidence")
    t_cve  = build_lookup(vulns, "x_mitre_emb3d_threat_CVEs")
    t_cwe  = build_lookup(vulns, "x_mitre_emb3d_threat_CWEs")

    m_desc = build_lookup(mitigs, "description")
    m_regs = build_lookup(mitigs, "x_mitre_emb3d_mitigation_regulatory_mapping")
    m_lvl  = build_lookup(mitigs, "x_mitre_emb3d_mitigation_level")

    header = [
        "Property ID", "Property text",
        "Threat ID", "Threat text", "Threat Description", "Threat Proof of Concept", "CVE", "CWE",
        "Mitigation ID", "Mitigation Text", "Mitigation Level", "Mitigation Description", "Mitigation Regulatory Mapping",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(header)

        # relationship.source_ref → relationship.target_ref determines linkage.
        for rel in rels:
            if rel.get("relationship_type") != "mitigates":
                continue

            tid = rel["target_ref"]   # vulnerability (Threat)
            mid = rel["source_ref"]    # course-of-action (Mitigation)

            threat = vulns.get(tid, {})
            mitig  = mitigs.get(mid, {})

            for prop_id in threat.get("x_mitre_emb3d_threat_properties", []):
                prop_text = threat.get("x_mitre_emb3d_threat_category", "")

                wr.writerow([
                    prop_id, prop_text,
                    tid, threat.get("name", ""), t_desc[tid], t_poc[tid], t_cve[tid], t_cwe[tid],
                    mid,  mitig.get("name", ""), m_lvl[mid], m_desc[mid], m_regs[mid],
                ])

    print(f"[ok] wrote {path} ({path.stat().st_size/1024:.1f} KiB)")


# -----------------------------------------------------------------------------
# CLI entry‑point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build EMB3D mapping CSV from the latest STIX bundle (no HTML scraping)")
    ap.add_argument("-o", "--output", default="emb3d_mapping.csv", type=Path,
                    help="Destination CSV file (default: emb3d_mapping.csv)")
    args = ap.parse_args()

    fname, url = latest_stix_info()
    print(f"[info] latest STIX bundle: {fname}\n       -> {url}\n")

    stix_bundle = load_stix_bundle(url)
    write_csv(args.output, stix_bundle)