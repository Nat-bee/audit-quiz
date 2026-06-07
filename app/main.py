import os
import threading
import time

import boto3
import trino
from botocore.exceptions import ClientError
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

TRINO_HOST = os.environ.get("TRINO_HOST", "localhost")
TRINO_PORT = int(os.environ.get("TRINO_PORT", "8080"))
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
DATA_PATH = os.environ.get("DATA_PATH", "/data/cloudtrail-events.jsonl")
CATALOG = "hive"
SCHEMA = "security_logs"

_ready = threading.Event()

QUIZZES = [
    {
        "id": 1,
        "level": "Basic",
        "title": "イベント総数",
        "description": "CloudTrailログに記録されたイベントの総数を求めよ。",
        "hint": "SELECT COUNT(*) FROM cloudtrail_logs",
        "validate": {"type": "scalar", "value": 2900},
    },
    {
        "id": 2,
        "level": "Basic",
        "title": "イベントソースの一覧",
        "description": "どのAWSサービスのイベントが記録されているか？ユニークなイベントソースの数を求めよ。",
        "hint": "SELECT COUNT(DISTINCT eventsource) FROM cloudtrail_logs",
        "validate": {"type": "scalar", "value": 29},
    },
    {
        "id": 3,
        "level": "Intermediate",
        "title": "ユーザーの特定",
        "description": "useridentityカラム（JSON文字列）からuserNameを抽出し、ユニークなユーザー名の一覧を取得せよ。",
        "hint": "JSON_EXTRACT_SCALAR(useridentity, '$.userName') を使う",
        "validate": {
            "type": "contains_value",
            "column": "_col0",
            "substring": "bert-jan",
            "expected_count": None,
        },
    },
    {
        "id": 4,
        "level": "Intermediate",
        "title": "不正アクセスの検出",
        "description": "errorcodeが 'AccessDenied' または 'Client.UnauthorizedOperation' のイベントを全て取得せよ。",
        "hint": "WHERE errorcode IN ('AccessDenied', 'Client.UnauthorizedOperation')",
        "validate": {"type": "scalar", "value": 60},
    },
    {
        "id": 5,
        "level": "Intermediate",
        "title": "権限昇格の検出",
        "description": "IAMポリシーの変更（PutRolePolicy, AttachRolePolicy）イベントを全て取得し、時系列で並べよ。実行者と変更内容を確認せよ。",
        "hint": "WHERE eventname IN ('PutRolePolicy', 'AttachRolePolicy') ORDER BY eventtime",
        "validate": {"type": "min_rows", "count": 11},
    },
    {
        "id": 6,
        "level": "Advanced",
        "title": "証拠隠滅の試み",
        "description": "攻撃者がCloudTrailの証跡を無効化・削除しようとした痕跡を見つけよ（DeleteTrail, StopLogging）。成功と失敗を区別せよ。",
        "hint": "WHERE eventname IN ('DeleteTrail', 'StopLogging') — errorcodeカラムで成否を判定",
        "validate": {
            "type": "contains_any",
            "column": "eventname",
            "substrings": ["DeleteTrail", "StopLogging"],
        },
    },
    {
        "id": 7,
        "level": "Advanced",
        "title": "永続化アクセスの確立",
        "description": "攻撃者がバックドアとして作成したIAMユーザー・認証情報を特定せよ（CreateUser, CreateAccessKey, CreateLoginProfile）。",
        "hint": "WHERE eventname IN ('CreateUser', 'CreateAccessKey', 'CreateLoginProfile') ORDER BY eventtime",
        "validate": {"type": "min_rows", "count": 8},
    },
]


def init_minio():
    s3 = boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
    )
    for attempt in range(30):
        try:
            for bucket in ("cloudtrail-logs", "trino-metastore"):
                try:
                    s3.create_bucket(Bucket=bucket)
                except ClientError as e:
                    if e.response["Error"]["Code"] != "BucketAlreadyOwnedByYou":
                        raise
            s3.upload_file(DATA_PATH, "cloudtrail-logs", "events/cloudtrail-events.jsonl")
            print("MinIO ready: data uploaded to s3://cloudtrail-logs/events/")
            return True
        except Exception as e:
            print(f"MinIO init attempt {attempt + 1}/30: {e}")
            time.sleep(2)
    return False


def init_trino():
    for attempt in range(60):
        try:
            conn = trino.dbapi.connect(
                host=TRINO_HOST, port=TRINO_PORT, user="quiz", catalog=CATALOG
            )
            cur = conn.cursor()

            cur.execute(f"CREATE SCHEMA IF NOT EXISTS {CATALOG}.{SCHEMA}")
            cur.fetchone()

            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {CATALOG}.{SCHEMA}.cloudtrail_logs (
                    eventversion        VARCHAR,
                    useridentity        VARCHAR,
                    eventtime           VARCHAR,
                    eventsource         VARCHAR,
                    eventname           VARCHAR,
                    awsregion           VARCHAR,
                    sourceipaddress     VARCHAR,
                    useragent           VARCHAR,
                    errorcode           VARCHAR,
                    errormessage        VARCHAR,
                    requestparameters   VARCHAR,
                    responseelements    VARCHAR,
                    additionaleventdata VARCHAR,
                    requestid           VARCHAR,
                    eventid             VARCHAR,
                    readonly            VARCHAR,
                    eventtype           VARCHAR,
                    managementevent     VARCHAR,
                    recipientaccountid  VARCHAR,
                    eventcategory       VARCHAR,
                    resources           VARCHAR,
                    tlsdetails          VARCHAR,
                    sharedeventid       VARCHAR,
                    vpcendpointid       VARCHAR,
                    apiversion          VARCHAR
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
            return True
        except Exception as e:
            print(f"Trino init attempt {attempt + 1}/60: {e}")
            time.sleep(3)
    return False


def init_all():
    if init_minio():
        init_trino()


def get_connection():
    return trino.dbapi.connect(
        host=TRINO_HOST, port=TRINO_PORT, user="quiz",
        catalog=CATALOG, schema=SCHEMA,
    )


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
        return False, "クエリでエラーが発生しました。"

    v = quiz["validate"]
    rows = result["rows"]
    columns = result["columns"]

    if v["type"] == "scalar":
        if not rows or not rows[0]:
            return False, f"期待値: {v['value']}、結果: なし"
        try:
            actual = int(rows[0][0])
        except (ValueError, IndexError):
            return False, f"期待値: 数値、結果: {rows[0][0]}"
        if actual == v["value"]:
            return True, f"正解！ {actual} 件です。"
        return False, f"期待値: {v['value']}、結果: {actual}"

    if v["type"] == "all_match":
        col_idx = columns.index(v["column"]) if v["column"] in columns else -1
        if col_idx == -1:
            return False, f"カラム '{v['column']}' が結果に含まれていません。"
        if not rows:
            return False, "結果が0行です。"
        mismatches = [r for r in rows if r[col_idx] != v["value"]]
        if mismatches:
            return False, f"{len(mismatches)} 行が '{v['value']}' と一致しません。"
        return True, f"正解！ 全 {len(rows)} 行が一致しています。"

    if v["type"] == "min_rows":
        if len(rows) >= v["count"]:
            return True, f"正解！ {len(rows)} 行見つかりました。"
        return False, f"期待値: {v['count']} 行以上、結果: {len(rows)} 行"

    if v["type"] == "contains_value":
        col_names_lower = [c.lower() for c in columns]
        target = v["column"].lower()
        col_idx = -1
        for i, c in enumerate(col_names_lower):
            if c == target or target in c:
                col_idx = i
                break
        if col_idx == -1 and columns:
            col_idx = 0
        if col_idx == -1:
            return False, f"カラム '{v['column']}' が結果に含まれていません。"
        matches = [r for r in rows if v["substring"] in r[col_idx]]
        expected = v.get("expected_count")
        if not matches:
            return False, f"'{v['substring']}' を含む行が見つかりません。"
        if expected and len(matches) != expected:
            return False, f"期待値: {expected} 件、結果: {len(matches)} 件"
        return True, f"正解！ '{v['substring']}' を含む行が {len(matches)} 件見つかりました。"

    if v["type"] == "contains_any":
        col_names_lower = [c.lower() for c in columns]
        target = v["column"].lower()
        col_idx = -1
        for i, c in enumerate(col_names_lower):
            if c == target:
                col_idx = i
                break
        if col_idx == -1:
            return False, f"カラム '{v['column']}' が結果に含まれていません。"
        found = set()
        for r in rows:
            for sub in v["substrings"]:
                if sub in r[col_idx]:
                    found.add(sub)
        if found:
            return True, f"正解！ 検出: {', '.join(sorted(found))}"
        return False, "該当するイベントが見つかりません。"

    return False, "不明な検証タイプです。"


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
        return jsonify({"error": "クエリが空です"}), 400

    forbidden = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "TRUNCATE"]
    upper_sql = sql.upper()
    for kw in forbidden:
        if kw in upper_sql:
            return jsonify({"error": f"変更クエリ ({kw}) は許可されていません"}), 400

    result = execute_query(sql)
    return jsonify(result)


@app.route("/api/validate", methods=["POST"])
def api_validate():
    quiz_id = request.json.get("quiz_id")
    sql = request.json.get("sql", "").strip()

    quiz = next((q for q in QUIZZES if q["id"] == quiz_id), None)
    if not quiz:
        return jsonify({"error": "不明なクイズです"}), 404

    result = execute_query(sql)
    if result.get("error"):
        return jsonify({"correct": False, "message": result["error"], "result": result})

    correct, message = validate_result(quiz, result)
    return jsonify({"correct": correct, "message": message, "result": result})


if __name__ == "__main__":
    threading.Thread(target=init_all, daemon=True).start()
    app.run(host="0.0.0.0", port=3000, debug=False)
