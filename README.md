# GRC Pipeline — Runbook

**System:** CloudGoat Lab System
**Baseline:** NIST 800-53r5 Moderate
**Owner:** GRC Engineer
**Last Updated:** 2024-01-15

---

## Overview

This pipeline automates evidence collection and POA&M generation for a
cloud-hosted system assessed against a NIST 800-53r5 Moderate control baseline.

It ingests Prowler OCSF JSON output, maps findings to specific 800-53 controls,
persists evidence to a SQLite audit store, and generates both a CSV POA&M
and an HTML compliance dashboard.

**Architecture:**

```
Prowler (scanner) → input/<scan>.ocsf.json   (OCSF Detection Findings)
        ↓
grc_pipeline.py (enrichment layer)
        ↓ reads
prowler_mappings.json → translates check IDs to control IDs
controls.json         → provides control metadata
        ↓ writes
grc_evidence.db       → SQLite evidence store (audit trail)
        ↓ outputs
poam_<scan_id>.csv    → federal POA&M format
dashboard_<scan_id>.html → stakeholder dashboard
```

---

## Prerequisites

- Python 3.11+
- No external dependencies (stdlib only: json, csv, sqlite3, argparse, uuid, datetime)
- For live scanning: Prowler v3.x, AWS credentials configured

---

## Running the Pipeline

### Against an OCSF Scan File

Drop a Prowler OCSF JSON file into `input/` and run:

```bash
cd grc-pipeline
python3 src/grc_pipeline.py --input input/<scan>.ocsf.json
```

The default `--input` points to the bundled scan in `input/`, so omitting
the flag also works once a file is in place.

### Against Live Prowler Output

```bash
# 1. Run Prowler and export OCSF JSON
prowler aws --output-formats ocsf-json --output-directory ./input

# 2. Feed output into pipeline
python3 src/grc_pipeline.py --input input/<filename>.ocsf.json
```

### Filter by Date (continuous monitoring mode)

```bash
# Only process findings from scans after a given date
python3 src/grc_pipeline.py \
    --input input/<scan>.ocsf.json \
    --since 2024-01-01
```

### Output Format Options

```bash
--format csv   # POA&M CSV only
--format html  # Dashboard only
--format both  # Default — both outputs
```

---

## File Reference

| File | Purpose |
|------|---------|
| `data/controls.json` | NIST 800-53r5 control definitions. Add controls here when expanding scope. |
| `data/prowler_mappings.json` | Translates Prowler check IDs to control IDs. Update when Prowler adds new checks. |
| `input/` | Drop Prowler OCSF JSON scan files here. Contents are gitignored. |
| `src/grc_pipeline.py` | Main pipeline. Loader → Enrichment → Persistence → Reporting. |
| `grc_evidence.db` | SQLite evidence store. Contains scans, findings, and evidence tables. |
| `output/` | Generated POA&M CSVs and HTML dashboards. |

---

## Design Decisions

### Why separate controls.json from prowler_mappings.json?

Controls change infrequently (800-53r5 is a stable standard).
Scanners change more often — Prowler releases new check IDs, or the
organization may switch to Security Hub or a commercial tool.

Keeping the mapping layer separate means the scanner can be swapped
by updating one file without touching the control library or the
pipeline business logic.

### Why SQLite for evidence storage?

- Zero infrastructure dependency — works offline, in CI, in a container
- Creates a tamper-evident audit trail (INSERT OR REPLACE preserves history)
- Easy to query for auditors: `SELECT * FROM findings WHERE severity='critical'`
- Straightforward to migrate to PostgreSQL for a production deployment

### Why is the remediation lookup in Python rather than JSON?

Remediation text is logic-adjacent — it may eventually need to pull from
a live knowledge base API or include dynamic resource ARNs. Starting in
code keeps it extensible without a schema change.

---

## Expanding the Pipeline

### Adding a new control

Edit `data/controls.json` — add an entry following the existing schema.

### Adding a new Prowler check mapping

Edit `data/prowler_mappings.json` — add an entry with the exact
`prowler_check_id` string (find this in Prowler's check documentation)
and the corresponding `maps_to_controls` array.

### Adding a new CloudGoat scenario

1. Deploy the scenario via `./cloudgoat.py create <scenario_name>`
2. Run Prowler against the resulting environment
3. Feed the JSON output to the pipeline

---

## Evidence Retention

All findings are persisted to `grc_evidence.db` with:
- `scan_id` — links finding to the originating scan
- `created_at` — automatic timestamp on insert
- `evidence` table — records source tool, collection timestamp, and raw output

This creates the auditable evidence chain required for RMF continuous
monitoring and POA&M milestone tracking.

To query the evidence store directly:

```bash
sqlite3 grc_evidence.db "SELECT finding_id, severity, finding_title FROM findings ORDER BY severity"
```

---

## POA&M Remediation Timelines

Scheduled completion dates are calculated from scan timestamp per severity:

| Severity | Window |
|----------|--------|
| Critical | 15 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |
| Informational | 365 days |

These align to common federal POA&M remediation guidance. Adjust in
`REMEDIATION_DAYS` in `grc_pipeline.py` to match your AO's requirements.
