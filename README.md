# CloudTrail Investigation Quiz

Pre-learning exercise for Security Camp 2026 D2. Query CloudTrail logs with SQL to investigate an AI agent compromise.

Uses [DuckDB](https://duckdb.org/) to query JSONL data directly — no cloud services, no API keys, no large image downloads. The SQL dialect is compatible with Athena/Presto.

## Scenario

An AI coding agent (`claude-code-agent`) was integrated into a company's CI/CD pipeline. After a prompt injection attack, the agent performed unauthorized actions including privilege escalation, data exfiltration, and evidence destruction. Your task is to analyze the CloudTrail logs and reconstruct the attack timeline.

## Prerequisites

- Docker & Docker Compose

## Quick Start

```bash
make up
# Open http://localhost:3000
```

### Without Docker

```bash
pip install flask duckdb
DATA_DIR=./data python app/main.py
# Open http://localhost:3000
```

## Codespaces

Open this directory in a Codespace — the quiz app starts automatically and the browser tab opens on port 3000.

## Terminal Mode (DuckDB CLI)

```bash
# Install DuckDB CLI: https://duckdb.org/docs/installation/
duckdb

# In DuckDB shell:
CREATE VIEW cloudtrail_logs AS
SELECT * FROM read_json_auto('data/cloudtrail-events.jsonl', format='newline_delimited');

SELECT * FROM cloudtrail_logs LIMIT 5;
```

## Table Schema

**Table**: `cloudtrail_logs`

| Column | Type | Description |
|--------|------|-------------|
| eventtime | VARCHAR | ISO 8601 timestamp |
| eventsource | VARCHAR | AWS service (e.g. `iam.amazonaws.com`) |
| eventname | VARCHAR | API action (e.g. `AttachRolePolicy`) |
| awsregion | VARCHAR | AWS region |
| sourceipaddress | VARCHAR | Source IP |
| useragent | VARCHAR | Client identifier |
| usertype | VARCHAR | `IAMUser` / `AssumedRole` / `AWSService` |
| userarn | VARCHAR | IAM ARN of the caller |
| username | VARCHAR | IAM user or role name |
| requestparameters | VARCHAR | Request parameters (JSON string) |
| responseelements | VARCHAR | Response data (JSON string) |
| eventid | VARCHAR | Unique event ID |
| readonly | VARCHAR | `true` if read-only |
| errorcode | VARCHAR | Error code (empty if success) |
| errormessage | VARCHAR | Error message (empty if success) |

## Architecture

```
┌─────────────┐      ┌─────────────────────────────┐
│  Browser     │      │  Docker                      │
│  :3000       │─────▶│  ┌──────────┐  ┌──────────┐ │
│              │      │  │ Flask    │──│ DuckDB   │ │
│              │      │  │ Web UI   │  │ (in-proc)│ │
│              │      │  └──────────┘  └──────────┘ │
│              │      │       ↓                      │
│              │      │  data/cloudtrail-events.jsonl│
└─────────────┘      └─────────────────────────────┘
```

## Note on Athena Compatibility

DuckDB's SQL dialect is largely compatible with Athena (Presto/Trino). Key differences:

- Use `LIKE` for pattern matching (same as Athena)
- String functions (`SUBSTR`, `LENGTH`, etc.) work the same
- Use `json_extract_string()` instead of Athena's `JSON_EXTRACT_SCALAR()`
- No database prefix needed — query `cloudtrail_logs` directly instead of `security_logs.cloudtrail_logs`
