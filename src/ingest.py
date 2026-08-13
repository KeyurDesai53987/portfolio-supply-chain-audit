#!/usr/bin/env python3
"""Resolve committed portfolio requirements and query exact versions against OSV."""
import hashlib
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_REPO = ROOT.parent / "rideshare-marketplace-analysis"
SOURCE_REQUIREMENTS = SOURCE_REPO / "requirements.txt"
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"


def post_json(url, payload):
    request = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json", "User-Agent": "portfolio-supply-chain-audit/1.0"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def get_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "portfolio-supply-chain-audit/1.0"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def main():
    RAW.mkdir(parents=True, exist_ok=True)
    PROCESSED.mkdir(parents=True, exist_ok=True)
    requirements = RAW / "source-requirements.txt"
    source_commit = subprocess.run(["git", "-C", str(SOURCE_REPO), "rev-parse", "HEAD"], check=True,
                                   capture_output=True, text=True).stdout.strip()
    committed_requirements = subprocess.run(
        ["git", "-C", str(SOURCE_REPO), "show", f"{source_commit}:requirements.txt"],
        check=True, capture_output=True).stdout
    requirements.write_bytes(committed_requirements)
    report = RAW / "pip-resolution.json"
    subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
                    "--report", str(report), "-r", str(requirements)], check=True)
    resolved = json.loads(report.read_text())
    packages = sorted({(item["metadata"]["name"], item["metadata"]["version"])
                       for item in resolved["install"]}, key=lambda item: item[0].lower())
    lock_path = PROCESSED / "requirements.lock"
    lock_lines = ["# Platform-specific lock generated from the captured pip report.",
                  "# Install with: pip install --require-hashes -r data/processed/requirements.lock"]
    for item in sorted(resolved["install"], key=lambda value: value["metadata"]["name"].lower()):
        hashes = item.get("download_info", {}).get("archive_info", {}).get("hashes", {})
        sha256 = hashes.get("sha256")
        if not sha256:
            raise RuntimeError(f"No SHA-256 distribution hash for {item['metadata']['name']}")
        lock_lines.append(f"{item['metadata']['name']}=={item['metadata']['version']} --hash=sha256:{sha256}")
    lock_path.write_text("\n".join(lock_lines) + "\n")
    queries = [{"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
               for name, version in packages]
    batch = post_json("https://api.osv.dev/v1/querybatch", {"queries": queries})
    if any(result.get("next_page_token") for result in batch["results"]):
        raise RuntimeError("OSV returned pagination; extend collector before accepting this snapshot")
    vulnerability_ids = sorted({vuln["id"] for result in batch["results"] for vuln in result.get("vulns", [])})
    details = [get_json(f"https://api.osv.dev/v1/vulns/{vulnerability_id}") for vulnerability_id in vulnerability_ids]
    osv_path = RAW / "osv-results.json"
    osv_path.write_text(json.dumps({"packages": [{"name": n, "version": v} for n, v in packages],
                                     "batch_results": batch["results"], "vulnerabilities": details}, indent=2) + "\n")
    manifest = {
        "subject_repository": "KeyurDesai53987/rideshare-marketplace-analysis",
        "subject_commit": source_commit,
        "subject_requirements_url": f"https://github.com/KeyurDesai53987/rideshare-marketplace-analysis/blob/{source_commit}/requirements.txt",
        "resolver": f"pip {resolved['pip_version']} --dry-run --ignore-installed --report",
        "osv_api": "https://api.osv.dev/v1/querybatch",
        "osv_documentation": "https://google.github.io/osv.dev/api/",
        "retrieved_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "direct_requirements": sum(1 for line in requirements.read_text().splitlines() if line and not line.startswith("#")),
        "resolved_packages": len(packages),
        "matched_vulnerability_ids": len(vulnerability_ids),
        "sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in (requirements, report, osv_path)},
        "lock_artifact": {"path": "data/processed/requirements.lock",
                          "sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest()},
        "scope": "Resolution is platform- and Python-version-specific; source records are factual snapshots, not generated dependencies.",
    }
    (RAW / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"resolved {len(packages)} packages and retrieved {len(vulnerability_ids)} exact-version OSV matches")


if __name__ == "__main__":
    main()
