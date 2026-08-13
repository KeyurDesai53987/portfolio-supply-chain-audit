import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"


def main():
    manifest = json.loads((RAW / "source-manifest.json").read_text())
    failures = []
    for filename, expected in manifest["sha256"].items():
        if hashlib.sha256((RAW / filename).read_bytes()).hexdigest() != expected:
            failures.append(f"hash:{filename}")
    lock_path = ROOT / manifest["lock_artifact"]["path"]
    if hashlib.sha256(lock_path.read_bytes()).hexdigest() != manifest["lock_artifact"]["sha256"]:
        failures.append("hash:requirements.lock")
    data = json.loads((RAW / "osv-results.json").read_text())
    if len(data["packages"]) != manifest["resolved_packages"]:
        failures.append("resolved-package-count")
    if len(data["packages"]) != len(data["batch_results"]):
        failures.append("query-response-alignment")
    identities = {(item["name"].lower(), item["version"]) for item in data["packages"]}
    if len(identities) != len(data["packages"]):
        failures.append("duplicate-package-version")
    locked = {line.split(" --hash=", 1)[0].lower() for line in lock_path.read_text().splitlines()
              if line and not line.startswith("#")}
    expected_locked = {f"{item['name']}=={item['version']}".lower() for item in data["packages"]}
    if locked != expected_locked:
        failures.append("lock-package-coverage")
    if any("--hash=sha256:" not in line for line in lock_path.read_text().splitlines()
           if line and not line.startswith("#")):
        failures.append("lock-missing-hash")
    returned_ids = {item["id"] for result in data["batch_results"] for item in result.get("vulns", [])}
    detail_ids = {item["id"] for item in data["vulnerabilities"]}
    if returned_ids != detail_ids:
        failures.append("missing-vulnerability-details")
    if failures:
        raise SystemExit("validation failed: " + ", ".join(failures))
    print(f"validated hashes, {len(identities)} locked package versions, response alignment, and OSV detail coverage")


if __name__ == "__main__":
    main()
