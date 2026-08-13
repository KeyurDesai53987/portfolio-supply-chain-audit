# Threat model and decision record

## Assets and threats

The protected asset is reproducibility and informed dependency remediation for a real portfolio repository. Threats include resolver drift, incomplete vulnerability responses, package/version misalignment, duplicated results, missing advisory detail, and overstatement of clean scans.

## Why exact-version OSV queries

A package-name query answers whether any advisory exists for a project. It does not establish that the resolved version is affected. Each query therefore supplies both PyPI name and exact resolved version. OSV evaluates that version against its affected ranges.

## Why capture the pip report

The source repository pins three direct requirements, but pip resolves nine additional packages. Capturing the resolver report makes the full selected set inspectable. The pipeline also emits a platform-specific `--require-hashes` lock containing every resolved package and the SHA-256 of the selected distribution, turning the observed drift risk into a reproducible remediation artifact.

The input is extracted from `HEAD:requirements.txt` with `git show`. Reading the committed blob—rather than copying the working-tree path—keeps the recorded commit and captured bytes inseparable.

## Negative result policy

The current snapshot has no OSV matches. The repository retains that result because manufacturing a vulnerable version would no longer audit the actual project. “No known match at retrieval time” is the strongest supported conclusion.

## Remediation design

If future scans return matches, the analyzer preserves OSV IDs and fixed-version events. A maintainer must still evaluate reachability, deployment context, breaking-change risk, and test results before upgrading. Automated severity claims are avoided when source records do not provide comparable scores.
