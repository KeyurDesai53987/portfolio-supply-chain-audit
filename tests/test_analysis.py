import json
import unittest
from pathlib import Path


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.osv = json.loads((self.root / "data" / "raw" / "osv-results.json").read_text())
        self.report = json.loads((self.root / "data" / "raw" / "pip-resolution.json").read_text())
        self.requirements = (self.root / "data" / "raw" / "source-requirements.txt").read_text().splitlines()

    def test_every_captured_package_has_one_aligned_osv_result(self):
        self.assertEqual(len(self.osv["packages"]), len(self.osv["batch_results"]))
        self.assertGreater(len(self.osv["packages"]), 0)

    def test_direct_requirements_exist_in_resolved_snapshot(self):
        direct = {line.split("==", 1)[0].lower() for line in self.requirements if line and not line.startswith("#")}
        resolved = {item["name"].lower() for item in self.osv["packages"]}
        self.assertTrue(direct.issubset(resolved))

    def test_every_resolved_distribution_has_a_factual_sha256(self):
        for item in self.report["install"]:
            digest = item["download_info"]["archive_info"]["hashes"]["sha256"]
            self.assertEqual(len(digest), 64)
            int(digest, 16)


if __name__ == "__main__":
    unittest.main()
