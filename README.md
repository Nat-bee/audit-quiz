# CloudTrail Investigation Quiz

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Nat-bee/seccamp-2026-d2?devcontainer_path=.devcontainer/athena-quiz/devcontainer.json)

Pre-learning exercise for Security Camp 2026 D2. Query real CloudTrail logs with Athena-compatible SQL to investigate a [Stratus Red Team](https://stratus-red-team.cloud/) attack simulation.

Uses [Trino](https://trino.io/) (the engine behind Amazon Athena) + [MinIO](https://min.io/) (S3-compatible storage). SQL syntax is identical to Athena — no dialect differences, no API keys.

## Data Source

[invictus-ir/aws_dataset](https://github.com/invictus-ir/aws_dataset) — 2,900 CloudTrail events from a Stratus Red Team attack simulation (2023-07-10, ~1 hour window). Covers 29 AWS services including IAM, EC2, S3, Secrets Manager, SSM, KMS, and CloudTrail.

## Quick Start

```bash
make up
# Open http://localhost:3000
# Trino initialization takes ~30s on first run
```

## Codespaces (One-Click)

Click the badge above or use the link below — services start automatically and the quiz opens in your browser.

```
https://codespaces.new/Nat-bee/seccamp-2026-d2?devcontainer_path=.devcontainer/athena-quiz/devcontainer.json
```

## Terminal Mode (Trino CLI)

```bash
# Connect to Trino
docker compose exec trino trino

# In Trino shell:
USE hive.security_logs;
SELECT * FROM cloudtrail_logs LIMIT 5;

-- JSON fields:
SELECT JSON_EXTRACT_SCALAR(useridentity, '$.userName') AS username
FROM cloudtrail_logs
LIMIT 10;
```

## Table Schema

**Database**: `security_logs`
**Table**: `cloudtrail_logs`

| Column | Type | Description |
|--------|------|-------------|
| eventversion | VARCHAR | CloudTrail event format version |
| useridentity | VARCHAR | Caller identity (JSON — use `JSON_EXTRACT_SCALAR`) |
| eventtime | VARCHAR | ISO 8601 timestamp |
| eventsource | VARCHAR | AWS service (e.g. `iam.amazonaws.com`) |
| eventname | VARCHAR | API action (e.g. `AttachRolePolicy`) |
| awsregion | VARCHAR | AWS region |
| sourceipaddress | VARCHAR | Source IP |
| useragent | VARCHAR | Client identifier |
| errorcode | VARCHAR | Error code (empty if success) |
| errormessage | VARCHAR | Error message (empty if success) |
| requestparameters | VARCHAR | Request parameters (JSON string) |
| responseelements | VARCHAR | Response data (JSON string) |
| additionaleventdata | VARCHAR | Additional data (JSON string) |
| requestid | VARCHAR | AWS request ID |
| eventid | VARCHAR | Unique event ID |
| readonly | VARCHAR | `true` if read-only |
| eventtype | VARCHAR | Event type |
| managementevent | VARCHAR | Management event flag |
| recipientaccountid | VARCHAR | Recipient account ID |
| eventcategory | VARCHAR | Event category |

## Architecture

![Architecture](assets/architecture.png)
