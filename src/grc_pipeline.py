#!/usr/bin/env python3
"""
GRC Pipeline - Automated Compliance Evidence Collector and POA&M Generator
Maps Prowler findings to NIST 800-53r5 controls and outputs a POA&M report.

Input format: Prowler OCSF JSON — a flat array of OCSF Detection Finding
records, as emitted natively by Prowler 4.x / 5.x.

Supports four output modes:
  csv       — POA&M in CSV format (CSAM-import compatible)
  html      — Stakeholder dashboard
  both      — CSV + HTML (default)
  regscale  — Push findings directly to RegScale via REST API

Usage:
    python grc_pipeline.py
    python grc_pipeline.py --input input/prowler-output-337443291158-20260510084116.ocsf.json
    python grc_pipeline.py --format csv
    python grc_pipeline.py --format html
    python grc_pipeline.py --format regscale
    python grc_pipeline.py --since 2024-01-01

RegScale environment variables (required for --format regscale):
    REGSCALE_URL       Base URL of your RegScale instance
                       e.g. https://yourorg.regscale.com
    REGSCALE_TOKEN     API token from RegScale user profile settings
    REGSCALE_PLAN_ID   Integer ID of the Security Plan your system is
                       registered under in RegScale
"""

import csv
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

import argparse


# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("grc-pipeline")


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

BASE_DIR      = Path(__file__).parent.parent
DATA_DIR      = BASE_DIR / "data"
INPUT_DIR     = BASE_DIR / "input"
OUTPUT_DIR    = BASE_DIR / "output"
DB_PATH       = BASE_DIR / "grc_evidence.db"

CONTROLS_FILE = DATA_DIR / "controls.json"
MAPPINGS_FILE = DATA_DIR / "prowler_mappings.json"
DEFAULT_INPUT = INPUT_DIR / "prowler-output-337443291158-20260510084116.ocsf.json"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

# FISMA-aligned remediation windows (days from scan date)
REMEDIATION_DAYS = {
    "critical":      15,
    "high":          30,
    "medium":        90,
    "low":           180,
    "informational": 365,
}

# RegScale severity integers (1 = most severe)
SEVERITY_TO_REGSCALE = {
    "critical":      1,
    "high":          2,
    "medium":        3,
    "low":           4,
    "informational": 5,
}


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

def init_db(conn: sqlite3.Connection) -> None:
    """
    Initialize the evidence store.

    Schema mirrors a real GRC platform data model:
      scans          — one row per Prowler run, immutable audit anchor
      findings       — one row per failing check per resource
      evidence       — audit trail linking findings to raw artifacts
      regscale_sync  — tracks what has been pushed to RegScale so we can
                       deduplicate on subsequent runs without extra API calls
    """
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id         TEXT PRIMARY KEY,
            system_name     TEXT NOT NULL,
            impact_level    TEXT NOT NULL,
            scan_timestamp  TEXT NOT NULL,
            aws_account_id  TEXT,
            scanner         TEXT,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id          TEXT PRIMARY KEY,
            scan_id             TEXT NOT NULL,
            prowler_check_id    TEXT NOT NULL,
            affected_resource   TEXT NOT NULL,
            region              TEXT,
            control_ids         TEXT NOT NULL,
            finding_title       TEXT NOT NULL,
            severity            TEXT NOT NULL,
            status              TEXT NOT NULL,
            raw_output          TEXT,
            remediation         TEXT,
            poam_eligible       INTEGER DEFAULT 1,
            cloudgoat_scenario  TEXT,
            created_at          TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        );

        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id     TEXT PRIMARY KEY,
            finding_id      TEXT NOT NULL,
            evidence_type   TEXT NOT NULL,
            source          TEXT NOT NULL,
            collected_at    TEXT NOT NULL,
            notes           TEXT,
            FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
        );

        CREATE TABLE IF NOT EXISTS regscale_sync (
            finding_id          TEXT PRIMARY KEY,
            regscale_issue_id   INTEGER NOT NULL,
            regscale_plan_id    INTEGER NOT NULL,
            pushed_at           TEXT NOT NULL,
            last_updated_at     TEXT,
            FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
        );
    """)
    conn.commit()


def get_synced_findings(conn: sqlite3.Connection) -> dict:
    """
    Return {finding_id: regscale_issue_id} for all findings already
    pushed to RegScale. Used as the fast-path deduplication check
    before making any API calls.
    """
    rows = conn.execute(
        "SELECT finding_id, regscale_issue_id FROM regscale_sync"
    ).fetchall()
    return {row[0]: row[1] for row in rows}


def record_regscale_sync(
    conn: sqlite3.Connection,
    finding_id: str,
    regscale_issue_id: int,
    plan_id: int,
    is_update: bool = False,
) -> None:
    """Write or refresh the RegScale sync record for a finding."""
    now = datetime.now(timezone.utc).isoformat()
    if is_update:
        conn.execute(
            "UPDATE regscale_sync SET last_updated_at = ? WHERE finding_id = ?",
            (now, finding_id),
        )
    else:
        conn.execute(
            """INSERT OR IGNORE INTO regscale_sync
               (finding_id, regscale_issue_id, regscale_plan_id, pushed_at)
               VALUES (?, ?, ?, ?)""",
            (finding_id, regscale_issue_id, plan_id, now),
        )
    conn.commit()


# ─────────────────────────────────────────────
# LOADERS
# ─────────────────────────────────────────────

def load_controls(path: Path) -> dict:
    with open(path) as f:
        data = json.load(f)
    return {c["control_id"]: c for c in data["controls"]}


def load_mappings(path: Path) -> dict:
    with open(path) as f:
        data = json.load(f)
    return {m["prowler_check_id"]: m for m in data["prowler_mappings"]}


# OCSF severity strings → the lowercase severity vocabulary used elsewhere.
# Prowler emits "Informational" / "Low" / "Medium" / "High" / "Critical".
_OCSF_SEVERITY = {
    "critical":      "critical",
    "high":          "high",
    "medium":        "medium",
    "low":           "low",
    "informational": "informational",
    "info":          "informational",
    "unknown":       "informational",
}


def load_prowler_output(path: Path, system_name: str, impact_level: str) -> dict:
    """
    Load a Prowler OCSF JSON file and return the canonical
    `{scan_metadata, raw_findings}` shape the rest of the pipeline expects.

    OCSF input is a flat JSON array of Detection Finding records (Prowler's
    native 4.x/5.x output). It has no top-level scan_metadata block, so we
    synthesize one from the first finding's `unmapped.scan_id`,
    `cloud.account.uid`, and `time_dt`.

    `system_name` and `impact_level` are FISMA system attributes that don't
    live in scanner output and are injected by the caller.

    Field mapping (OCSF → raw_findings entry):
      metadata.event_code      → prowler_check_id
      status_code              → status            (PASS/FAIL/MANUAL/MUTED, verbatim)
      resources[0].uid         → affected_resource
      resources[0].region      → region            (cloud.region as fallback)
      status_detail | message  → raw_output
      severity                 → severity
      remediation.desc         → remediation_hint
    """
    with open(path) as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(
            f"Expected an OCSF JSON array in {path}, got {type(data).__name__}."
        )
    if not data:
        raise ValueError(f"OCSF input {path} is empty — no findings to process.")

    first = data[0]
    unmapped = first.get("unmapped") or {}
    cloud    = first.get("cloud") or {}
    account  = cloud.get("account") or {}
    product  = (first.get("metadata") or {}).get("product") or {}

    scan_metadata = {
        "scan_id":        unmapped.get("scan_id") or f"SCAN-{uuid.uuid4().hex[:8].upper()}",
        "system_name":    system_name,
        "impact_level":   impact_level,
        "scan_timestamp": first.get("time_dt")
                          or (first.get("finding_info") or {}).get("created_time_dt")
                          or datetime.now(timezone.utc).isoformat(),
        "aws_account_id": account.get("uid") or unmapped.get("provider_uid"),
        "aws_region":     cloud.get("region"),
        "scanner":        (product.get("name") or "prowler").lower(),
    }

    raw_findings = []
    for ocsf in data:
        resources = ocsf.get("resources") or []
        primary   = resources[0] if resources else {}
        cloud_f   = ocsf.get("cloud") or {}

        raw_findings.append({
            "prowler_check_id": (ocsf.get("metadata") or {}).get("event_code", ""),
            "status":           ocsf.get("status_code", ""),
            "affected_resource": primary.get("uid")
                                 or primary.get("name")
                                 or "unknown",
            "region":           primary.get("region")
                                or cloud_f.get("region")
                                or "us-east-1",
            "raw_output":       ocsf.get("status_detail")
                                or ocsf.get("message", ""),
            "severity":         _OCSF_SEVERITY.get(
                                    (ocsf.get("severity") or "").lower(),
                                    "informational",
                                ),
            "remediation_hint": (ocsf.get("remediation") or {}).get("desc", ""),
        })

    return {"scan_metadata": scan_metadata, "raw_findings": raw_findings}


# ─────────────────────────────────────────────
# ENRICHMENT
# ─────────────────────────────────────────────

def enrich_findings(
    raw_findings: list,
    mappings: dict,
    controls: dict,
    scan_id: str,
    since: Optional[datetime] = None,
) -> list:
    """
    Translate raw Prowler output into enriched finding records.

    This is the GRC intelligence layer. The mapping file translates
    scanner-specific check IDs into control IDs so the scanner can be
    swapped (Prowler → Security Hub → commercial tool) by updating
    prowler_mappings.json without touching this logic or the control library.
    """
    enriched = []
    for raw in raw_findings:
        if raw["status"] != "FAIL":
            continue

        check_id = raw["prowler_check_id"]
        if check_id not in mappings:
            log.warning("No mapping for check %s — skipping", check_id)
            continue

        mapping = mappings[check_id]
        resolved_controls = []
        for cid in mapping["maps_to_controls"]:
            if cid in controls:
                resolved_controls.append(controls[cid])
            else:
                log.warning("Control %s in mapping but not in library", cid)

        enriched.append({
            "finding_id":         f"FIND-{uuid.uuid4().hex[:8].upper()}",
            "scan_id":            scan_id,
            "prowler_check_id":   check_id,
            "affected_resource":  raw["affected_resource"],
            "region":             raw.get("region", "us-east-1"),
            "control_ids":        mapping["maps_to_controls"],
            "controls_detail":    resolved_controls,
            "finding_title":      mapping["finding_title"],
            "severity":           mapping["default_severity"],
            "status":             raw["status"],
            "raw_output":         raw.get("raw_output", ""),
            "cloudgoat_scenario": mapping.get("cloudgoat_scenario"),
            "poam_eligible":      True,
            "remediation":        build_remediation_text(check_id),
        })

    return enriched


def build_remediation_text(check_id: str) -> str:
    remediation_map = {
        "iam_user_mfa_enabled_console_access":
            "Enable MFA for the IAM user via IAM console or CLI: aws iam enable-mfa-device",
        "iam_policy_attached_only_to_groups_or_roles":
            "Detach policy from user and attach to an IAM group or role instead",
        "iam_administrator_access_with_mfa":
            "Enable MFA immediately for admin accounts; consider scoping down AdministratorAccess",
        "cloudtrail_multi_region_enabled":
            "Enable multi-region logging: aws cloudtrail update-trail --is-multi-region-trail",
        "cloudtrail_log_file_validation_enabled":
            "Enable log file validation: aws cloudtrail update-trail --enable-log-file-validation",
        "cloudtrail_s3_bucket_is_not_publicly_accessible":
            "Enable S3 Block Public Access on the CloudTrail log destination bucket",
        "cloudtrail_cloudwatch_logging_enabled":
            "Associate a CloudWatch Logs log group with the CloudTrail trail",
        "s3_bucket_public_access":
            "Enable S3 Block Public Access at both the bucket and account level",
        "s3_bucket_server_side_encryption_enabled":
            "Enable default encryption on the S3 bucket using SSE-S3 or SSE-KMS",
        "s3_bucket_secure_transport_policy":
            "Add a bucket policy condition requiring aws:SecureTransport = true",
        "s3_bucket_logging_enabled":
            "Enable S3 server access logging and direct logs to a dedicated audit bucket",
        "ec2_imdsv2_enabled":
            "Set IMDSv2 as required: aws ec2 modify-instance-metadata-options --http-tokens required",
        "ec2_instance_profile_attached":
            "Attach an IAM instance profile with least-privilege permissions to the EC2 instance",
        "cognito_identity_pool_guest_access_disabled":
            "Disable unauthenticated access in the Cognito identity pool settings",
        "cognito_user_pool_mfa_enabled":
            "Enable MFA in the Cognito user pool settings (TOTP or SMS)",
        "securityhub_enabled":
            "Enable AWS Security Hub: aws securityhub enable-security-hub",
    }
    return remediation_map.get(check_id, "Refer to AWS documentation for remediation guidance")


# ─────────────────────────────────────────────
# PERSISTENCE
# ─────────────────────────────────────────────

def persist_scan(conn: sqlite3.Connection, metadata: dict) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO scans
           (scan_id, system_name, impact_level, scan_timestamp, aws_account_id, scanner)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            metadata["scan_id"], metadata["system_name"], metadata["impact_level"],
            metadata["scan_timestamp"], metadata.get("aws_account_id"), metadata.get("scanner"),
        ),
    )
    conn.commit()


def persist_findings(conn: sqlite3.Connection, findings: list) -> None:
    for f in findings:
        conn.execute(
            """INSERT OR REPLACE INTO findings
               (finding_id, scan_id, prowler_check_id, affected_resource, region,
                control_ids, finding_title, severity, status, raw_output,
                remediation, poam_eligible, cloudgoat_scenario)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f["finding_id"], f["scan_id"], f["prowler_check_id"],
                f["affected_resource"], f["region"],
                json.dumps(f["control_ids"]),
                f["finding_title"], f["severity"], f["status"],
                f["raw_output"], f["remediation"],
                1 if f["poam_eligible"] else 0,
                f.get("cloudgoat_scenario"),
            ),
        )
        conn.execute(
            """INSERT INTO evidence
               (evidence_id, finding_id, evidence_type, source, collected_at, notes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                f"EV-{uuid.uuid4().hex[:8].upper()}",
                f["finding_id"], "automated_scan", "prowler",
                datetime.now(timezone.utc).isoformat(),
                f["raw_output"],
            ),
        )
    conn.commit()


# ─────────────────────────────────────────────
# REGSCALE CLIENT
# ─────────────────────────────────────────────

class RegScaleClient:
    """
    Thin REST client for the RegScale API.

    Wraps the four operations the pipeline needs:
      verify_connection       — confirm the instance is reachable before pushing
      find_issue_by_external_id — dedup check via externalId query param
      create_issue            — POST a new Issue record
      update_issue_due_date   — PATCH an existing issue's scheduled completion date
      attach_evidence         — POST raw scanner output as an Evidence record
                                linked to the issue

    Design decisions:
      - All methods return None / False on failure after logging the error.
        The pipeline degrades gracefully — a network blip doesn't corrupt
        the local evidence store or leave a partial push unrecorded.
      - The bearer token is read from an env var, never hardcoded.
        This is the correct pattern for CI/CD pipelines and a point
        worth raising in the interview if asked about secrets management.
      - A requests.Session is used so the Authorization header is sent
        on every request without repetition, and TCP connections are
        reused across the batch — matters for large finding sets.
    """

    def __init__(self, base_url: str, token: str, plan_id: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.plan_id  = plan_id
        self.session  = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        })

    # ── internal helpers ──

    def _get(self, path: str, params: dict = None) -> Optional[dict]:
        try:
            resp = self.session.get(
                f"{self.base_url}{path}", params=params, timeout=15
            )
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            log.error("GET %s → %s: %s", path, e.response.status_code, e.response.text[:200])
        except requests.RequestException as e:
            log.error("GET %s → network error: %s", path, e)
        return None

    def _post(self, path: str, payload: dict) -> Optional[dict]:
        try:
            resp = self.session.post(
                f"{self.base_url}{path}", json=payload, timeout=15
            )
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            log.error("POST %s → %s: %s", path, e.response.status_code, e.response.text[:200])
        except requests.RequestException as e:
            log.error("POST %s → network error: %s", path, e)
        return None

    def _patch(self, path: str, payload: dict) -> Optional[dict]:
        try:
            resp = self.session.patch(
                f"{self.base_url}{path}", json=payload, timeout=15
            )
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            log.error("PATCH %s → %s: %s", path, e.response.status_code, e.response.text[:200])
        except requests.RequestException as e:
            log.error("PATCH %s → network error: %s", path, e)
        return None

    # ── public API ──

    def verify_connection(self) -> bool:
        """
        Confirm the API is reachable and the token is valid.
        Fail fast — don't push anything if the connection is broken.
        Pushing half a batch and leaving the sync table in an
        inconsistent state is worse than not pushing at all.
        """
        result = self._get("/api/securityplans", params={"id": self.plan_id})
        if result is not None:
            log.info("RegScale connection verified — plan ID %d", self.plan_id)
            return True
        log.error(
            "RegScale connection failed. Check REGSCALE_URL, "
            "REGSCALE_TOKEN, and REGSCALE_PLAN_ID."
        )
        return False

    def find_issue_by_external_id(self, external_id: str) -> Optional[int]:
        """
        Search for an existing Issue by our internal finding_id stored
        as externalId in RegScale.

        This is the API fallback deduplication check — called only when
        a finding_id is NOT in the local regscale_sync table, which would
        happen if the SQLite DB was cleared or the pipeline ran on a
        different machine. Costs one GET per finding in this path.
        """
        result = self._get(
            "/api/issues",
            params={"externalId": external_id, "securityPlanId": self.plan_id},
        )
        if result and isinstance(result, list) and len(result) > 0:
            return result[0].get("id")
        return None

    def create_issue(self, finding: dict, due_date: str) -> Optional[int]:
        """
        POST a new Issue record to RegScale.

        Field mapping from finding → RegScale Issue schema:
          finding_title     → title
          raw_output        → description  (Prowler text as context)
          severity          → severityLevel (integer 1–5)
          control_ids       → controlId    (comma-separated NIST IDs)
          affected_resource → assetIdentifier
          remediation       → remediation
          due_date          → dateScheduled
          finding_id        → externalId   (our dedup key)
          plan_id           → securityPlanId

        Returns the new RegScale issue ID on success, None on failure.
        """
        payload = {
            "title":            finding["finding_title"],
            "description":      finding["raw_output"],
            "severityLevel":    SEVERITY_TO_REGSCALE.get(finding["severity"].lower(), 3),
            "status":           "Open",
            "controlId":        ", ".join(finding["control_ids"]),
            "assetIdentifier":  finding["affected_resource"],
            "remediation":      finding["remediation"],
            "dateScheduled":    due_date,
            "securityPlanId":   self.plan_id,
            "source":           "Prowler Automated Scan",
            "externalId":       finding["finding_id"],
        }
        result = self._post("/api/issues", payload)
        return result.get("id") if result else None

    def update_issue_due_date(self, issue_id: int, due_date: str) -> bool:
        """
        PATCH an existing issue to refresh its scheduled completion date.

        Called when a finding already exists in RegScale from a prior run.
        We don't re-create it but we do update the milestone date so the
        POA&M reflects the current scan's remediation timeline.
        """
        result = self._patch(f"/api/issues/{issue_id}", {"dateScheduled": due_date})
        return result is not None

    def attach_evidence(self, issue_id: int, finding: dict, scan_timestamp: str) -> bool:
        """
        POST raw Prowler output as an Evidence record linked to the issue.

        Evidence attachment creates the audit chain an assessor needs:
          Issue record  — what the problem is and what control it violates
          Evidence record — the raw scanner output that substantiates it

        In a real assessment, the assessor would open the issue in RegScale,
        click through to the evidence, and see the timestamped Prowler output
        that generated the finding. This satisfies the 'Examine' assessment
        method under NIST SP 800-53A.
        """
        payload = {
            "issueId":       issue_id,
            "title":         f"Prowler scan output — {finding['prowler_check_id']}",
            "description":   finding["raw_output"],
            "source":        "prowler",
            "evidenceType":  "Automated Scan Output",
            "collectedDate": scan_timestamp,
            "externalId":    f"{finding['finding_id']}-ev",
        }
        result = self._post("/api/evidence", payload)
        return result is not None


# ─────────────────────────────────────────────
# REGSCALE OUTPUT MODE
# ─────────────────────────────────────────────

def push_to_regscale(
    findings: list,
    metadata: dict,
    conn: sqlite3.Connection,
) -> None:
    """
    Push enriched findings to RegScale as Issue records.

    Flow per finding:
      1. Check regscale_sync table locally — O(1), no API call
         → If found: PATCH due date on existing issue, update sync record
      2. If not in local table, check RegScale API by externalId
         → Handles the case where SQLite was cleared or pipeline
           ran on a different machine
         → If found: record in sync table, skip creation
      3. If truly new: POST issue → attach evidence → record sync

    Environment variables required:
      REGSCALE_URL      — base URL of RegScale instance
      REGSCALE_TOKEN    — API bearer token
      REGSCALE_PLAN_ID  — integer security plan ID
    """
    if not REQUESTS_AVAILABLE:
        log.error("requests library not installed. Run: pip install requests")
        return

    base_url = os.environ.get("REGSCALE_URL", "").rstrip("/")
    token    = os.environ.get("REGSCALE_TOKEN", "")
    plan_id  = int(os.environ.get("REGSCALE_PLAN_ID", "0"))

    if not all([base_url, token, plan_id]):
        log.error(
            "Missing RegScale config. Required env vars:\n"
            "  REGSCALE_URL      = %s\n"
            "  REGSCALE_TOKEN    = %s\n"
            "  REGSCALE_PLAN_ID  = %s",
            "set" if base_url else "MISSING",
            "set" if token    else "MISSING",
            str(plan_id) if plan_id else "MISSING",
        )
        return

    client = RegScaleClient(base_url, token, plan_id)

    # Fail fast before touching any findings
    if not client.verify_connection():
        return

    # Load local sync state — fast path avoids API calls for already-pushed findings
    already_synced = get_synced_findings(conn)
    log.info(
        "Sync state: %d findings already pushed in prior runs",
        len(already_synced),
    )

    created = 0
    updated = 0
    skipped = 0
    failed  = 0

    for f in findings:
        due_date = calculate_due_date(f["severity"], metadata["scan_timestamp"])

        # ── FAST PATH: local dedup ──
        if f["finding_id"] in already_synced:
            issue_id = already_synced[f["finding_id"]]
            log.info(
                "  [SKIP] %s already synced as RegScale issue %d — refreshing due date",
                f["finding_id"], issue_id,
            )
            if client.update_issue_due_date(issue_id, due_date):
                record_regscale_sync(conn, f["finding_id"], issue_id, plan_id, is_update=True)
                updated += 1
            else:
                failed += 1
            continue

        # ── SLOW PATH: API dedup (SQLite cleared / new machine) ──
        existing_id = client.find_issue_by_external_id(f["finding_id"])
        if existing_id:
            log.info(
                "  [SKIP] %s found in RegScale via API (issue %d) — recording sync",
                f["finding_id"], existing_id,
            )
            record_regscale_sync(conn, f["finding_id"], existing_id, plan_id)
            skipped += 1
            continue

        # ── CREATE ──
        log.info("  [POST] %s", f["finding_title"][:70])
        issue_id = client.create_issue(f, due_date)

        if not issue_id:
            log.error("  [FAIL] Could not create issue for %s", f["finding_id"])
            failed += 1
            continue

        log.info("  [OK]   Created RegScale issue %d", issue_id)

        # Attach evidence — log warning but don't fail the whole push if this fails
        if client.attach_evidence(issue_id, f, metadata["scan_timestamp"]):
            log.info("  [OK]   Evidence attached to issue %d", issue_id)
        else:
            log.warning("  [WARN] Evidence attachment failed for issue %d", issue_id)

        record_regscale_sync(conn, f["finding_id"], issue_id, plan_id)
        created += 1

    log.info("")
    log.info("─── RegScale push complete ───────────────")
    log.info("  Created : %d", created)
    log.info("  Updated : %d  (due date refreshed)", updated)
    log.info("  Skipped : %d  (found via API, already existed)", skipped)
    log.info("  Failed  : %d", failed)
    if failed:
        log.warning(
            "%d findings failed. Re-run after fixing the issue — "
            "deduplication will skip already-synced items.", failed
        )


# ─────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────

def calculate_due_date(severity: str, scan_timestamp: str) -> str:
    days    = REMEDIATION_DAYS.get(severity.lower(), 90)
    scan_dt = datetime.fromisoformat(scan_timestamp.replace("Z", "+00:00"))
    return (scan_dt + timedelta(days=days)).strftime("%Y-%m-%d")


def generate_poam_csv(findings: list, metadata: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "POA&M ID", "System Name", "Control ID(s)", "Weakness / Finding",
        "Severity", "Affected Resource", "Region", "CloudGoat Scenario",
        "Raw Evidence", "Remediation Action", "Scheduled Completion Date",
        "Status", "Scan ID",
    ]
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f["severity"].lower())
        if f["severity"].lower() in SEVERITY_ORDER else 99,
    )
    with open(output_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for i, f in enumerate(sorted_findings, start=1):
            writer.writerow({
                "POA&M ID":                  f"POAM-{i:04d}",
                "System Name":               metadata["system_name"],
                "Control ID(s)":             ", ".join(f["control_ids"]),
                "Weakness / Finding":        f["finding_title"],
                "Severity":                  f["severity"].upper(),
                "Affected Resource":         f["affected_resource"],
                "Region":                    f["region"],
                "CloudGoat Scenario":        f.get("cloudgoat_scenario") or "N/A",
                "Raw Evidence":              f["raw_output"],
                "Remediation Action":        f["remediation"],
                "Scheduled Completion Date": calculate_due_date(f["severity"], metadata["scan_timestamp"]),
                "Status":                    "Open",
                "Scan ID":                   f["scan_id"],
            })
    log.info("POA&M CSV → %s", output_path)


def generate_summary_html(findings: list, metadata: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    by_severity = {s: 0 for s in SEVERITY_ORDER}
    by_family   = {}
    for f in findings:
        sev = f["severity"].lower()
        if sev in by_severity:
            by_severity[sev] += 1
        for ctrl in f.get("controls_detail", []):
            family = ctrl.get("family", "Unknown")
            by_family[family] = by_family.get(family, 0) + 1

    sev_colors = {
        "critical": "#d62728", "high": "#ff7f0e", "medium": "#f0c040",
        "low": "#2ca02c", "informational": "#aec7e8",
    }
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f["severity"].lower())
        if f["severity"].lower() in SEVERITY_ORDER else 99,
    )
    rows = ""
    for i, f in enumerate(sorted_findings, start=1):
        color = sev_colors.get(f["severity"].lower(), "#999")
        rows += (
            f"<tr><td>POAM-{i:04d}</td>"
            f"<td><span class='badge' style='background:{color}'>{f['severity'].upper()}</span></td>"
            f"<td>{', '.join(f['control_ids'])}</td>"
            f"<td>{f['finding_title']}</td>"
            f"<td class='resource'>{f['affected_resource']}</td>"
            f"<td>{f.get('cloudgoat_scenario') or 'N/A'}</td>"
            f"<td>{calculate_due_date(f['severity'], metadata['scan_timestamp'])}</td></tr>"
        )
    max_count = max(by_severity.values()) if any(by_severity.values()) else 1
    bars = ""
    for sev, count in by_severity.items():
        if not count:
            continue
        pct = int((count / max_count) * 100)
        color = sev_colors.get(sev, "#999")
        bars += (
            f"<div class='bar-row'>"
            f"<span class='bar-label'>{sev.capitalize()}</span>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{pct}%;background:{color}'></div></div>"
            f"<span class='bar-count'>{count}</span></div>"
        )
    family_items = "".join(
        f"<li><strong>{fam}</strong>: {cnt} finding(s)</li>"
        for fam, cnt in sorted(by_family.items(), key=lambda x: -x[1])
    )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>GRC Pipeline — Compliance Dashboard</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e0e0e0;padding:2rem}}
h1{{font-size:1.6rem;color:#fff;margin-bottom:.25rem}}
h2{{font-size:1.1rem;color:#aaa;font-weight:400;margin-bottom:2rem}}
h3{{font-size:1rem;color:#ccc;margin-bottom:1rem}}
.meta{{display:flex;gap:2rem;flex-wrap:wrap;margin-bottom:2rem}}
.meta-item{{background:#1a1d27;padding:1rem 1.5rem;border-radius:8px;border:1px solid #2a2d3a}}
.meta-item .label{{font-size:.75rem;color:#777;text-transform:uppercase;letter-spacing:.05em}}
.meta-item .value{{font-size:1.2rem;color:#fff;font-weight:600;margin-top:.25rem}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem}}
.card{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:8px;padding:1.5rem}}
.bar-row{{display:flex;align-items:center;gap:.75rem;margin-bottom:.6rem}}
.bar-label{{width:90px;font-size:.85rem;color:#aaa;text-align:right}}
.bar-track{{flex:1;background:#2a2d3a;border-radius:4px;height:18px}}
.bar-fill{{height:100%;border-radius:4px}}
.bar-count{{width:24px;font-size:.85rem;color:#ccc}}
ul{{list-style:none;padding:0}}
li{{padding:.4rem 0;border-bottom:1px solid #2a2d3a;font-size:.9rem;color:#bbb}}
li:last-child{{border-bottom:none}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{background:#1a1d27;color:#aaa;text-align:left;padding:.6rem .8rem;font-weight:500;border-bottom:1px solid #2a2d3a}}
td{{padding:.6rem .8rem;border-bottom:1px solid #1e2130;vertical-align:top}}
tr:hover td{{background:#1e2130}}
.badge{{display:inline-block;padding:.2rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700;color:#fff}}
.resource{{font-family:monospace;font-size:.78rem;color:#aaa;word-break:break-all}}
.table-wrap{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:8px;overflow-x:auto;padding:1rem}}
.footer{{margin-top:2rem;font-size:.75rem;color:#555;text-align:center}}
</style></head><body>
<h1>GRC Pipeline — Compliance Dashboard</h1>
<h2>NIST 800-53r5 | Moderate Baseline | {metadata['system_name']}</h2>
<div class="meta">
  <div class="meta-item"><div class="label">Scan ID</div><div class="value" style="font-size:.95rem">{metadata['scan_id']}</div></div>
  <div class="meta-item"><div class="label">Timestamp</div><div class="value" style="font-size:.95rem">{metadata['scan_timestamp']}</div></div>
  <div class="meta-item"><div class="label">AWS Account</div><div class="value" style="font-size:.95rem">{metadata.get('aws_account_id','N/A')}</div></div>
  <div class="meta-item"><div class="label">Impact Level</div><div class="value">{metadata['impact_level'].upper()}</div></div>
  <div class="meta-item"><div class="label">Open Findings</div><div class="value" style="color:#d62728">{len(findings)}</div></div>
</div>
<div class="grid">
  <div class="card"><h3>Findings by Severity</h3>{bars}</div>
  <div class="card"><h3>Findings by Control Family</h3><ul>{family_items}</ul></div>
</div>
<div class="table-wrap">
  <h3 style="margin-bottom:1rem">Open POA&amp;M Items</h3>
  <table>
    <thead><tr><th>POA&amp;M ID</th><th>Severity</th><th>Control(s)</th>
    <th>Finding</th><th>Affected Resource</th><th>Scenario</th><th>Due Date</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">Generated by GRC Pipeline &mdash; Scanner: {metadata.get('scanner','N/A')}
&mdash; {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</div>
</body></html>"""

    with open(output_path, "w") as fh:
        fh.write(html)
    log.info("HTML dashboard → %s", output_path)


# ─────────────────────────────────────────────
# CONSOLE SUMMARY
# ─────────────────────────────────────────────

def print_summary(findings: list, metadata: dict) -> None:
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f["severity"].lower()
        if sev in by_sev:
            by_sev[sev] += 1
    print("\n" + "=" * 55)
    print(f"  GRC PIPELINE SUMMARY — {metadata['system_name']}")
    print("=" * 55)
    print(f"  Scan ID:        {metadata['scan_id']}")
    print(f"  Impact Level:   {metadata['impact_level'].upper()}")
    print(f"  Timestamp:      {metadata['scan_timestamp']}")
    print(f"  Total Findings: {len(findings)}")
    print()
    for sev in SEVERITY_ORDER:
        count = by_sev[sev]
        if count:
            print(f"  {sev.upper():14} {'█' * count} ({count})")
    print("=" * 55)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GRC Pipeline — NIST 800-53r5 compliance evidence collector and POA&M generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
output modes:
  csv       POA&M CSV (CSAM-import compatible)
  html      Stakeholder compliance dashboard
  both      CSV + HTML (default)
  regscale  Push findings to RegScale via REST API

regscale env vars (required for --format regscale):
  REGSCALE_URL        Base URL of your RegScale instance
  REGSCALE_TOKEN      API bearer token from user profile settings
  REGSCALE_PLAN_ID    Integer security plan ID in RegScale
        """,
    )
    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT),
        help=f"Path to Prowler OCSF JSON output file. Default: {DEFAULT_INPUT}",
    )
    parser.add_argument(
        "--system-name", default="CloudGoat Lab System",
        help="FISMA system name to record on the scan (OCSF input has no system_name field).",
    )
    parser.add_argument(
        "--impact-level", default="moderate",
        choices=["low", "moderate", "high"],
        help="FISMA impact level to record on the scan (default: moderate).",
    )
    parser.add_argument(
        "--since", default=None,
        help="Only process scans after this date (YYYY-MM-DD). Supports continuous monitoring cadence.",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "html", "both", "regscale"],
        default="both",
        help="Output format (default: both)",
    )
    args = parser.parse_args()

    log.info("GRC Pipeline starting — output: %s", args.format)

    log.info("Loading control library and mappings...")
    controls = load_controls(CONTROLS_FILE)
    mappings = load_mappings(MAPPINGS_FILE)
    log.info("  Controls: %d  |  Mappings: %d", len(controls), len(mappings))

    log.info("Loading Prowler output: %s", args.input)
    prowler_data = load_prowler_output(Path(args.input), args.system_name, args.impact_level)
    metadata     = prowler_data["scan_metadata"]
    raw_findings = prowler_data["raw_findings"]
    log.info("  Raw findings: %d", len(raw_findings))

    since_dt = None
    if args.since:
        since_dt = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc)
        scan_dt  = datetime.fromisoformat(metadata["scan_timestamp"].replace("Z", "+00:00"))
        if scan_dt < since_dt:
            log.warning(
                "Scan timestamp %s is before --since %s. Nothing to process.",
                metadata["scan_timestamp"], args.since,
            )
            return

    log.info("Enriching findings...")
    findings = enrich_findings(raw_findings, mappings, controls, metadata["scan_id"], since_dt)
    log.info("  Enriched FAIL findings: %d", len(findings))

    log.info("Persisting to evidence store: %s", DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    persist_scan(conn, metadata)
    persist_findings(conn, findings)
    log.info("  Evidence stored.")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.format in ("csv", "both"):
        generate_poam_csv(findings, metadata, OUTPUT_DIR / f"poam_{metadata['scan_id']}_{ts}.csv")

    if args.format in ("html", "both"):
        generate_summary_html(findings, metadata, OUTPUT_DIR / f"dashboard_{metadata['scan_id']}_{ts}.html")

    if args.format == "regscale":
        log.info("Pushing to RegScale...")
        push_to_regscale(findings, metadata, conn)

    conn.close()
    print_summary(findings, metadata)
    log.info("Pipeline complete.")


if __name__ == "__main__":
    main()
