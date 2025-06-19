#!/usr/bin/env python3
"""
MITRE EMB3D CSV Builder
Author      : Jason Bisnette
Created     : March 2025
Last Updated: June 2025

Purpose
-------
Rebuild the entire EMB3D mapping (PID -> TID -> MID) into a flattened .csv.

    • Uses MITRE's STIX bundle from the public GitHub repo and
      flattens it.
    • Scrapes every Threat (TID-###) and Mitigation (MID-###) page to collect
      descriptions, Proof-of-Concept links, CVEs, CWEs, and regulatory mappings
    • Produces a flat, analysis-ready CSV with one row per PID -> TID -> MID

Features
--------
* **Auto-discovers the newest STIX file** in
  `https://github.com/mitre/emb3d/tree/main/assets/` (version-aware).
* **Zero external deps** beyond the Python 3 stdlib
  (- optional `packaging` for nicer version sorting).

Usage
-----
    python3 build_emb3d_csv_from_stix.py                # → emb3d_mapping.csv
    python3 build_emb3d_csv_from_stix.py -o out.csv     # custom output name

License
-------
This script is released under the MIT License.
MITRE EMB3D™ content is © MITRE and used under its Terms of Use.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
import urllib.request as urlreq
from urllib.error import HTTPError, URLError

# optional, for proper semver sorting; if unavailable, falls back to lexical
try:
    from packaging.version import Version
except ImportError:
    Version = None  # type: ignore

ASSETS_API = "https://api.github.com/repos/mitre/emb3d/contents/assets"
SEMVER_RX = re.compile(r"emb3d-stix-(\d+\.\d+\.\d+)\.json")


def latest_stix_info() -> tuple[str, str]:
    """Return (filename, download_url) of the newest STIX JSON in /assets."""
    try:
        with urlreq.urlopen(ASSETS_API, timeout=30) as resp:
            entries = json.load(resp)
    except (HTTPError, URLError) as e:
        sys.exit(f"[fatal] Cannot list assets/: {e}")

    stix_files = [
        (e["name"], e["download_url"])
        for e in entries
        if e["name"].startswith("emb3d-stix-") and e["name"].endswith(".json")
    ]
    if not stix_files:
        sys.exit("[fatal] No STIX files found under assets/ – repo layout changed?")

    # sort by semver (if available) or by filename
    if Version:
        try:
            stix_files.sort(
                key=lambda t: Version(SEMVER_RX.search(t[0]).group(1)),
                reverse=True
            )
        except Exception:
            stix_files.sort(reverse=True)
    else:
        stix_files.sort(reverse=True)

    return stix_files[0]


def load_stix_bundle(url: str) -> dict:
    """Download & parse the STIX bundle at `url`."""
    try:
        with urlreq.urlopen(url, timeout=60) as resp:
            return json.load(resp)
    except (HTTPError, URLError) as e:
        sys.exit(f"[fatal] Unable to fetch STIX bundle: {e}")


def split_objects(objects: list[dict]) -> tuple[dict, dict, dict, list[dict]]:
    """
    Partition the STIX objects into:
      - vulnerabilities (threats)
      - mitigations (course-of-action)
      - properties (x-mitre-emb3d-property)
      - raw relationships
    """
    vulns = {o["id"]: o for o in objects if o.get("type") == "vulnerability"}
    mitigs = {o["id"]: o for o in objects if o.get("type") == "course-of-action"}
    props = {o["id"]: o for o in objects if o.get("type") == "x-mitre-emb3d-property"}
    rels = [o for o in objects if o.get("type") == "relationship"]
    return vulns, mitigs, props, rels


def build_lookup(objs: dict[str, dict], field: str) -> dict[str, str]:
    """Make a lookup dict {id: obj[field] or ''} for quick access."""
    return {oid: o.get(field, "") or "" for oid, o in objs.items()}


def write_csv(path: Path, bundle: dict) -> None:
    """Extract all PID→TID→MID rows and write the CSV to `path`."""
    vulns, mitigs, props, rels = split_objects(bundle.get("objects", []))

    # build threat → [property IDs] from 'relates-to' relationships
    prop_map: dict[str, list[str]] = {}
    for r in rels:
        if r.get("relationship_type") == "relates-to":
            pid = r["source_ref"]
            tid = r["target_ref"]
            prop_map.setdefault(tid, []).append(pid)

    # lookups for STIX custom fields
    t_desc = build_lookup(vulns, "description")
    t_poc_raw = build_lookup(vulns, "x_mitre_emb3d_threat_evidence")
    t_cve_raw = build_lookup(vulns, "x_mitre_emb3d_threat_CVEs")
    t_cwe_raw = build_lookup(vulns, "x_mitre_emb3d_threat_CWEs")

    m_desc = build_lookup(mitigs, "description")
    m_regs_raw = build_lookup(mitigs, "x_mitre_emb3d_mitigation_IEC_62443_mappings")
    m_lvl = build_lookup(mitigs, "x_mitre_emb3d_mitigation_maturity")

    header = [
        "Property ID", "Property text",
        "Threat ID", "Threat text", "Threat Description", "Threat Proof of Concept", "CVE", "CWE",
        "Mitigation ID", "Mitigation Text", "Mitigation Level", "Mitigation Description", "Mitigation Regulatory Mapping",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)

        # for every mitigation relationship, emit one row per property on that threat
        for r in rels:
            if r.get("relationship_type") != "mitigates":
                continue

            tid = r["target_ref"]    # vulnerability
            mid = r["source_ref"]    # course-of-action

            threat = vulns.get(tid, {})
            mitig  = mitigs.get(mid, {})

            # extract threat fields
            threat_id = threat.get("x_mitre_emb3d_threat_id", "")
            threat_name = threat.get("name", "")
            threat_desc = t_desc.get(tid, "")
            # parse PoC bullets: Markdown list of [text](url)
            poc_list = []
            for line in t_poc_raw.get(tid, "").splitlines():
                line = line.strip()
                if line.startswith("- "):
                    m = re.match(r"- \[([^\]]+)\]\(([^)]+)\)", line)
                    if m:
                        poc_list.append(f"{m.group(1)} ({m.group(2)})")
            threat_poc = "; ".join(poc_list)
            # parse CVEs & CWEs
            cves = re.findall(r"(CVE-\d{4}-\d+)", t_cve_raw.get(tid, ""))
            cwes = re.findall(r"(CWE-\d+)", t_cwe_raw.get(tid, ""))
            threat_cve = "; ".join(cves)
            threat_cwe = "; ".join(cwes)

            # parse mitigation fields
            mitig_id = mitig.get("x_mitre_emb3d_mitigation_id", "")
            mitig_name = mitig.get("name", "")
            mitig_lvl = m_lvl.get(mid, "")
            mitig_desc = m_desc.get(mid, "")
            regs = []
            for line in m_regs_raw.get(mid, "").splitlines():
                line = line.strip()
                if line.startswith("- "):
                    regs.append(line.lstrip("- ").strip())
            mitig_regs = "; ".join(regs)

            # for each property on this threat
            for pid in prop_map.get(tid, []):
                prop = props.get(pid, {})
                prop_id = prop.get("x_mitre_emb3d_property_id", "")
                prop_text = prop.get("name", "")

                writer.writerow([
                    prop_id, prop_text,
                    threat_id, threat_name, threat_desc, threat_poc, threat_cve, threat_cwe,
                    mitig_id, mitig_name, mitig_lvl, mitig_desc, mitig_regs,
                ])

    print(f"[ok] Wrote {path} ({path.stat().st_size/1024:.1f} KiB)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Build EMB3D mapping CSV from the latest STIX bundle (no HTML scraping)"
    )
    ap.add_argument(
        "-o", "--output",
        default="emb3d_mapping.csv",
        type=Path,
        help="Destination CSV file (default: emb3d_mapping.csv)"
    )
    args = ap.parse_args()

    fname, url = latest_stix_info()
    print(f"[info] Latest STIX bundle: {fname}\n       → {url}\n")

    bundle = load_stix_bundle(url)
    write_csv(args.output, bundle)
