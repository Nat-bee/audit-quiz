# CloudTrail Investigation Quiz

Pre-learning exercise for Security Camp 2026 D2. Query CloudTrail logs with Athena-compatible SQL to investigate an AI agent compromise.

Uses [Trino](https://trino.io/) (the engine behind Amazon Athena) + [MinIO](https://min.io/) (S3-compatible storage). SQL syntax is identical to Athena — no dialect differences, no API keys.

## Scenario

An AI coding agent (`claude-code-agent`) was integrated into a company's CI/CD pipeline. After a prompt injection attack, the agent performed unauthorized actions including privilege escalation, data exfiltration, and evidence destruction. Your task is to analyze the CloudTrail logs and reconstruct the attack timeline.

## Prerequisites

- Docker & Docker Compose

## Quick Start

```bash
make up
# Open http://localhost:3000
# Trino initialization takes ~30s on first run
```

## Codespaces

Open this directory in a Codespace — services start automatically and the browser tab opens on port 3000.

## Terminal Mode (Trino CLI)

```bash
# Connect to Trino
docker compose exec trino trino

# In Trino shell:
USE hive.security_logs;
SELECT * FROM cloudtrail_logs LIMIT 5;
```

## Table Schema

**Database**: `security_logs`
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
┌─────────────┐      ┌──────────────────────────────────────┐
│  Browser     │      │  Docker Compose                      │
│  :3000       │─────▶│  ┌──────────┐    ┌───────────────┐  │
│              │      │  │ Quiz App │───▶│  Trino        │  │
│  Terminal    │      │  │ (Flask)  │    │  (Athena SQL) │  │
│  trino CLI   │─────▶│  └──────────┘    │       │        │  │
│              │      │                  │       ▼        │  │
│              │      │                  │  ┌──────────┐  │  │
│              │      │                  │  │  MinIO   │  │  │
│              │      │                  │  │  (S3)    │  │  │
│              │      │                  │  │  JSONL   │  │  │
│              │      │                  │  └──────────┘  │  │
│              │      │                  └───────────────┘  │
└─────────────┘      └──────────────────────────────────────┘
```

## Why Trino, not LocalStack or DuckDB?

| Engine | Athena SQL compatibility | Dependencies | Startup |
|--------|------------------------|--------------|---------|
| LocalStack Pro Athena | Identical | Pro license + 1.5GB image | Minutes |
| DuckDB | Similar but differs (`json_extract_string` vs `JSON_EXTRACT_SCALAR`) | None | Instant |
| **Trino + MinIO** | **Identical** (Athena = managed Trino) | **Docker only** | **~30s** |
