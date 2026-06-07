#!/bin/bash
set -euo pipefail

echo "=== Setting up CloudTrail Athena Quiz Environment ==="

awslocal s3 mb s3://cloudtrail-logs 2>/dev/null || true
awslocal s3 mb s3://athena-results 2>/dev/null || true

echo "Uploading CloudTrail events..."
awslocal s3 cp /tmp/data/cloudtrail-events.jsonl s3://cloudtrail-logs/events/cloudtrail-events.jsonl

echo "Creating Athena database..."
QUERY_ID=$(awslocal athena start-query-execution \
  --query-string "CREATE DATABASE IF NOT EXISTS security_logs" \
  --result-configuration OutputLocation=s3://athena-results/ \
  --query 'QueryExecutionId' --output text)

echo "Waiting for database creation (ID: $QUERY_ID)..."
while true; do
  STATE=$(awslocal athena get-query-execution \
    --query-execution-id "$QUERY_ID" \
    --query 'QueryExecution.Status.State' --output text)
  if [ "$STATE" = "SUCCEEDED" ]; then break; fi
  if [ "$STATE" = "FAILED" ]; then
    echo "ERROR: Database creation failed"
    awslocal athena get-query-execution --query-execution-id "$QUERY_ID"
    exit 1
  fi
  sleep 2
done

echo "Creating CloudTrail table..."
CREATE_TABLE_SQL="CREATE EXTERNAL TABLE security_logs.cloudtrail_logs (
  eventtime STRING,
  eventsource STRING,
  eventname STRING,
  awsregion STRING,
  sourceipaddress STRING,
  useragent STRING,
  usertype STRING,
  userarn STRING,
  username STRING,
  requestparameters STRING,
  responseelements STRING,
  eventid STRING,
  readonly STRING,
  errorcode STRING,
  errormessage STRING
)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
LOCATION 's3://cloudtrail-logs/events/'"

QUERY_ID=$(awslocal athena start-query-execution \
  --query-string "$CREATE_TABLE_SQL" \
  --query-execution-context Database=security_logs \
  --result-configuration OutputLocation=s3://athena-results/ \
  --query 'QueryExecutionId' --output text)

echo "Waiting for table creation (ID: $QUERY_ID)..."
while true; do
  STATE=$(awslocal athena get-query-execution \
    --query-execution-id "$QUERY_ID" \
    --query 'QueryExecution.Status.State' --output text)
  if [ "$STATE" = "SUCCEEDED" ]; then break; fi
  if [ "$STATE" = "FAILED" ]; then
    echo "ERROR: Table creation failed"
    awslocal athena get-query-execution --query-execution-id "$QUERY_ID"
    exit 1
  fi
  sleep 2
done

echo "Verifying setup with test query..."
QUERY_ID=$(awslocal athena start-query-execution \
  --query-string "SELECT COUNT(*) AS total FROM security_logs.cloudtrail_logs" \
  --query-execution-context Database=security_logs \
  --result-configuration OutputLocation=s3://athena-results/ \
  --query 'QueryExecutionId' --output text)

while true; do
  STATE=$(awslocal athena get-query-execution \
    --query-execution-id "$QUERY_ID" \
    --query 'QueryExecution.Status.State' --output text)
  if [ "$STATE" = "SUCCEEDED" ]; then break; fi
  if [ "$STATE" = "FAILED" ]; then
    echo "WARNING: Test query failed, but setup may still work"
    break
  fi
  sleep 2
done

if [ "$STATE" = "SUCCEEDED" ]; then
  awslocal athena get-query-results --query-execution-id "$QUERY_ID"
fi

awslocal s3 cp - s3://athena-results/.setup-complete <<< "done"

echo "=== Setup complete ==="
