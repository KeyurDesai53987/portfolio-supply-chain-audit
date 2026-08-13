#!/usr/bin/env python3
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
RESULTS = ROOT / "results"


def fixed_versions(record, package_name):
    versions = set()
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != "PyPI" or package.get("name", "").lower() != package_name.lower():
            continue
        for range_item in affected.get("ranges", []):
            for event in range_item.get("events", []):
                if event.get("fixed"):
                    versions.add(event["fixed"])
    return sorted(versions)


def main():
    data = json.loads((RAW / "osv-results.json").read_text())
    direct_names = {line.split("==", 1)[0].strip().lower()
                    for line in (RAW / "source-requirements.txt").read_text().splitlines()
                    if line.strip() and not line.startswith("#")}
    vulnerabilities = {item["id"]: item for item in data["vulnerabilities"]}
    rows = []
    aliases = Counter()
    for package, result in zip(data["packages"], data["batch_results"]):
        ids = sorted({item["id"] for item in result.get("vulns", [])})
        fixes = sorted({version for vulnerability_id in ids
                        for version in fixed_versions(vulnerabilities[vulnerability_id], package["name"])})
        for vulnerability_id in ids:
            for alias in vulnerabilities[vulnerability_id].get("aliases", []):
                aliases[alias.split("-")[0]] += 1
        rows.append({"package": package["name"], "version": package["version"],
                     "dependency_type": "direct" if package["name"].lower() in direct_names else "transitive",
                     "osv_matches": len(ids), "osv_ids": "|".join(ids), "fixed_versions": "|".join(fixes)})
    PROCESSED.mkdir(parents=True, exist_ok=True); RESULTS.mkdir(exist_ok=True)
    with (PROCESSED / "package_exposure.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys()); writer.writeheader(); writer.writerows(rows)
    affected = [row for row in rows if row["osv_matches"]]
    summary = {"resolved_packages": len(rows), "direct_pinned_packages": sum(row["dependency_type"] == "direct" for row in rows),
               "transitive_resolver_selected_packages": sum(row["dependency_type"] == "transitive" for row in rows),
               "packages_with_osv_matches": len(affected),
               "unique_osv_records": len(vulnerabilities), "total_package_record_matches": sum(row["osv_matches"] for row in rows),
               "affected_packages": affected, "alias_prefix_counts": dict(aliases),
               "interpretation": "Zero matches means OSV returned no known records for these exact versions at retrieval time; it does not prove absence of vulnerabilities."}
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
