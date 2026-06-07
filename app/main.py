import os
import threading
import time

import trino
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

TRINO_HOST = os.environ.get("TRINO_HOST", "localhost")
TRINO_PORT = int(os.environ.get("TRINO_PORT", "8080"))
CATALOG = "hive"
SCHEMA = "security_logs"

_ready = threading.Event()

QUIZZES = [
    {
        "id": 1,
        "level": "Basic",
        "title": "Total Event Count",
        "description": "How many events are recorded in the CloudTrail logs?",
        "description_ja": "CloudTrailログに記録されたイベントの総数を求めよ。",
        "hint": "SELECT COUNT(*) FROM cloudtrail_logs",
        "validate": {"type": "scalar", "value": 30},
    },
    {
        "id": 2,
        "level": "Basic",
        "title": "IAM Events",
        "description": "List all IAM-related events. Show eventtime, eventname, username.",
        "description_ja": "IAMに関連するイベントを全て取得せよ（eventtime, eventname, username を表示）。",
        "hint": "WHERE eventsource = 'iam.amazonaws.com'",
        "validate": {"type": "all_match", "column": "eventsource", "value": "iam.amazonaws.com"},
    },
    {
        "id": 3,
        "level": "Basic",
        "title": "After-Hours Events",
        "description": "List all events that occurred after 23:00 UTC in chronological order.",
        "description_ja": "23:00 UTC以降に発生したイベントを時系列で一覧せよ。",
        "hint": "WHERE eventtime >= '2026-08-01T23:00:00Z' ORDER BY eventtime",
        "validate": {"type": "min_rows", "count": 14},
    },
    {
        "id": 4,
        "level": "Intermediate",
        "title": "Privilege Escalation",
        "description": "Identify events where AdministratorAccess policy was attached to any entity.",
        "description_ja": "AdministratorAccess ポリシーがアタッチされたイベントを特定せよ。",
        "hint": "requestparameters LIKE '%AdministratorAccess%'",
        "validate": {"type": "contains_value", "column": "requestparameters", "substring": "AdministratorAccess", "expected_count": 2},
    },
    {
        "id": 5,
        "level": "Intermediate",
        "title": "Abnormal S3 Access",
        "description": "Identify S3 accesses by claude-code-agent to buckets other than 'code-artifacts-prod'.",
        "description_ja": "claude-code-agent が通常アクセスしない S3 バケットへのアクセスを特定せよ（通常バケット: code-artifacts-prod）。",
        "hint": "username = 'claude-code-agent' AND eventsource = 's3.amazonaws.com' AND requestparameters NOT LIKE '%code-artifacts-prod%'",
        "validate": {"type": "contains_any", "column": "requestparameters", "substrings": ["customer-data-prod", "external-staging"]},
    },
    {
        "id": 6,
        "level": "Advanced",
        "title": "Attack Timeline Reconstruction",
        "description": "Reconstruct the full attack timeline. Categorize each phase: Reconnaissance, Privilege Escalation, Data Access, Persistence, Anti-Forensics.",
        "description_ja": "攻撃の全体タイムラインを再構成せよ。各フェーズを分類すること：偵察→権限昇格→データアクセス→永続化→証拠隠滅。",
        "hint": "23:00以降の claude-code-agent のイベントを時系列で並べ、各アクションが何を達成しているか考える。",
        "validate": {"type": "min_rows", "count": 10},
    },
    {
        "id": 7,
        "level": "Advanced",
        "title": "Failed Cover-Up",
        "description": "Did the attacker fail to destroy any evidence? Find events with errors.",
        "description_ja": "攻撃者の証拠隠滅の試みで失敗したものはあるか？エラーが発生したイベントを特定せよ。",
        "hint": "errorcode != '' (empty string means success)",
        "validate": {"type": "contains_value", "column": "errorcode", "substring": "AccessDenied", "expected_count": 1},
    },
]


def get_connection():
    return trino.dbapi.connect(
        host=TRINO_HOST,
        port=TRINO_PORT,
        user="quiz",
        catalog=CATALOG,
        schema=SCHEMA,
    )


def init_trino():
    for attempt in range(60):
        try:
            conn = trino.dbapi.connect(
                host=TRINO_HOST,
                port=TRINO_PORT,
                user="quiz",
                catalog=CATALOG,
            )
            cur = conn.cursor()

            cur.execute(f"CREATE SCHEMA IF NOT EXISTS {CATALOG}.{SCHEMA}")
            cur.fetchone()

            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {CATALOG}.{SCHEMA}.cloudtrail_logs (
                    eventtime      VARCHAR,
                    eventsource    VARCHAR,
                    eventname      VARCHAR,
                    awsregion      VARCHAR,
                    sourceipaddress VARCHAR,
                    useragent      VARCHAR,
                    usertype       VARCHAR,
                    userarn        VARCHAR,
                    username       VARCHAR,
                    requestparameters VARCHAR,
                    responseelements VARCHAR,
                    eventid        VARCHAR,
                    readonly       VARCHAR,
                    errorcode      VARCHAR,
                    errormessage   VARCHAR
                )
                WITH (
                    external_location = 's3a://cloudtrail-logs/events/',
                    format = 'JSON'
                )
            """)
            cur.fetchone()

            cur.execute(f"SELECT COUNT(*) FROM {CATALOG}.{SCHEMA}.cloudtrail_logs")
            count = cur.fetchone()[0]
            cur.close()
            conn.close()
            print(f"Trino ready: {count} events in cloudtrail_logs")
            _ready.set()
            return
        except Exception as e:
            print(f"Init attempt {attempt + 1}/60: {e}")
            time.sleep(3)

    print("ERROR: Failed to initialize Trino")


def execute_query(sql):
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(sql)
        columns = [desc[0] for desc in cur.description]
        rows = [[str(v) if v is not None else "" for v in row] for row in cur.fetchall()]
        cur.close()
        conn.close()
        return {"columns": columns, "rows": rows, "error": None}
    except Exception as e:
        return {"error": str(e), "rows": [], "columns": []}


def validate_result(quiz, result):
    if result.get("error"):
        return False, "Query returned an error."

    v = quiz["validate"]
    rows = result["rows"]
    columns = result["columns"]

    if v["type"] == "scalar":
        if not rows or not rows[0]:
            return False, f"Expected {v['value']}, got no results."
        try:
            actual = int(rows[0][0])
        except (ValueError, IndexError):
            return False, f"Expected a number, got: {rows[0][0]}"
        if actual == v["value"]:
            return True, f"Correct! {actual} events."
        return False, f"Expected {v['value']}, got {actual}."

    if v["type"] == "all_match":
        col_idx = columns.index(v["column"]) if v["column"] in columns else -1
        if col_idx == -1:
            return False, f"Column '{v['column']}' not found in results."
        if not rows:
            return False, "No rows returned."
        mismatches = [r for r in rows if r[col_idx] != v["value"]]
        if mismatches:
            return False, f"{len(mismatches)} rows don't match '{v['value']}'."
        return True, f"Correct! All {len(rows)} rows match."

    if v["type"] == "min_rows":
        if len(rows) >= v["count"]:
            return True, f"Correct! Found {len(rows)} rows."
        return False, f"Expected at least {v['count']} rows, got {len(rows)}."

    if v["type"] == "contains_value":
        col_idx = columns.index(v["column"]) if v["column"] in columns else -1
        if col_idx == -1:
            return False, f"Column '{v['column']}' not found in results."
        matches = [r for r in rows if v["substring"] in r[col_idx]]
        expected = v.get("expected_count")
        if not matches:
            return False, f"No rows contain '{v['substring']}'."
        if expected and len(matches) != expected:
            return False, f"Expected {expected} matches, found {len(matches)}."
        return True, f"Correct! Found {len(matches)} matching rows."

    if v["type"] == "contains_any":
        col_idx = columns.index(v["column"]) if v["column"] in columns else -1
        if col_idx == -1:
            return False, f"Column '{v['column']}' not found in results."
        found = set()
        for r in rows:
            for sub in v["substrings"]:
                if sub in r[col_idx]:
                    found.add(sub)
        if found:
            return True, f"Correct! Found accesses to: {', '.join(sorted(found))}."
        return False, "No unusual bucket accesses found."

    return False, "Unknown validation type."


@app.route("/")
def index():
    return render_template("index.html", quizzes=QUIZZES)


@app.route("/api/health")
def health():
    if _ready.is_set():
        return jsonify({"status": "ready"})
    return jsonify({"status": "initializing"}), 503


@app.route("/api/query", methods=["POST"])
def api_query():
    sql = request.json.get("sql", "").strip()
    if not sql:
        return jsonify({"error": "Empty query"}), 400

    forbidden = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "TRUNCATE"]
    upper_sql = sql.upper()
    for kw in forbidden:
        if kw in upper_sql:
            return jsonify({"error": f"Mutation queries ({kw}) are not allowed"}), 400

    result = execute_query(sql)
    return jsonify(result)


@app.route("/api/validate", methods=["POST"])
def api_validate():
    quiz_id = request.json.get("quiz_id")
    sql = request.json.get("sql", "").strip()

    quiz = next((q for q in QUIZZES if q["id"] == quiz_id), None)
    if not quiz:
        return jsonify({"error": "Unknown quiz"}), 404

    result = execute_query(sql)
    if result.get("error"):
        return jsonify({"correct": False, "message": result["error"], "result": result})

    correct, message = validate_result(quiz, result)
    return jsonify({"correct": correct, "message": message, "result": result})


if __name__ == "__main__":
    threading.Thread(target=init_trino, daemon=True).start()
    app.run(host="0.0.0.0", port=3000, debug=False)
