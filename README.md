# CloudTrail Investigation Quiz

Pre-learning exercise for Security Camp 2026 D2. Query CloudTrail logs with Athena on LocalStack to investigate an AI agent compromise.

## Scenario

An AI coding agent (`claude-code-agent`) was integrated into a company's CI/CD pipeline. After a prompt injection attack, the agent performed unauthorized actions including privilege escalation, data exfiltration, and evidence destruction. Your task is to analyze the CloudTrail logs and reconstruct the attack timeline.

## Prerequisites

- Docker & Docker Compose
- [LocalStack Pro auth token](https://app.localstack.cloud/) (Athena requires Pro)

## Quick Start

```bash
export LOCALSTACK_AUTH_TOKEN=<your-token>
make up
# Open http://localhost:3000
```

First startup downloads the Athena BigData image (~1.5GB). The quiz app shows "Initializing..." until setup completes.

## Codespaces

1. Set `LOCALSTACK_AUTH_TOKEN` as a Codespace secret
2. Open this directory in a Codespace — services start automatically

## Terminal Mode

Use `awslocal` to query directly:

```bash
pip install awscli-local

# Example
awslocal athena start-query-execution \
  --query-string "SELECT * FROM security_logs.cloudtrail_logs LIMIT 5" \
  --query-execution-context Database=security_logs \
  --result-configuration OutputLocation=s3://athena-results/ \
  --endpoint-url http://localhost:4566

# Get results (replace QUERY_ID)
awslocal athena get-query-results --query-execution-id <QUERY_ID>
```

## Table Schema

**Database**: `security_logs`
**Table**: `cloudtrail_logs`

| Column | Type | Description |
|--------|------|-------------|
| eventtime | STRING | ISO 8601 timestamp |
| eventsource | STRING | AWS service (e.g. `iam.amazonaws.com`) |
| eventname | STRING | API action (e.g. `AttachRolePolicy`) |
| awsregion | STRING | AWS region |
| sourceipaddress | STRING | Source IP |
| useragent | STRING | Client identifier |
| usertype | STRING | `IAMUser` / `AssumedRole` / `AWSService` |
| userarn | STRING | IAM ARN of the caller |
| username | STRING | IAM user or role name |
| requestparameters | STRING | Request parameters (JSON string) |
| responseelements | STRING | Response data (JSON string) |
| eventid | STRING | Unique event ID |
| readonly | STRING | `true` if read-only |
| errorcode | STRING | Error code (empty if success) |
| errormessage | STRING | Error message (empty if success) |

## Architecture

```
┌─────────────┐      ┌──────────────────────────────────────┐
│  Browser     │      │  Docker Compose                      │
│  :3000       │─────▶│  ┌──────────┐    ┌───────────────┐  │
│              │      │  │ Quiz App │───▶│  LocalStack    │  │
│  Terminal    │      │  │ (Flask)  │    │  (Athena+S3)   │  │
│  awslocal    │─────▶│  └──────────┘    │  :4566         │  │
│              │      │                  │  ┌───────────┐ │  │
│              │      │                  │  │ S3 Bucket │ │  │
│              │      │                  │  │ JSONL data│ │  │
│              │      │                  │  └───────────┘ │  │
│              │      │                  └───────────────┘  │
└─────────────┘      └──────────────────────────────────────┘
```
