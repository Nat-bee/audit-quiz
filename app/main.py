import os
import re
import threading
import time

import boto3
import trino
from botocore.exceptions import ClientError
from flask import Flask, jsonify, render_template, request

import telemetry

_ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_COMMENT_RE = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r"'(?:[^']|'')*'")
_PROHIBITED_KW_RE = re.compile(
    r"\b(UNION|EXCEPT|INTERSECT|LATERAL|VALUES)\b", re.IGNORECASE,
)
_CTE_RE = re.compile(r"^\s*WITH\b", re.IGNORECASE)
_TABLE_RE = re.compile(r"\bFROM\s+cloudtrail_logs\b", re.IGNORECASE)
_SUBQUERY_IN_SELECT_RE = re.compile(
    r"\bSELECT\b[^()]*\(", re.IGNORECASE,
)


def _strip_sql(sql):
    s = _COMMENT_RE.sub(" ", sql)
    return _STRING_RE.sub("''", s)


def _check_sql_structure(sql):
    stripped = _strip_sql(sql)
    if _CTE_RE.search(stripped):
        return False, "WITH句（CTE）は使用できません。"
    if _PROHIBITED_KW_RE.search(stripped):
        return False, "UNION/EXCEPT/INTERSECT/LATERAL/VALUESは使用できません。"
    if not _TABLE_RE.search(stripped):
        return False, "cloudtrail_logs テーブルをFROM句で参照してください。"
    return True, ""


def _check_scalar_sql(sql):
    stripped = _strip_sql(sql)
    select_match = re.match(r"\s*SELECT\s+(.*?)\s+FROM\b", stripped, re.IGNORECASE | re.DOTALL)
    if not select_match:
        return False, "SELECT ... FROM cloudtrail_logs の形式で書いてください。"
    select_expr = select_match.group(1)
    if re.search(r"\(", select_expr):
        if not re.search(r"\b(COUNT|SUM|AVG|MIN|MAX)\s*\(", select_expr, re.IGNORECASE):
            return False, "集約関数（COUNT等）を使ってください。サブクエリは使用できません。"
    else:
        if not re.search(r"\b(COUNT|SUM|AVG|MIN|MAX)\b", select_expr, re.IGNORECASE):
            return False, "集約関数（COUNT等）を使って件数を求めてください。"
    return True, ""

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
        "hint": "JSON_EXTRACT_SCALAR(useridentity, '$.userName') を使う。NULLに注意",
        "validate": {
            "type": "contains_value",
            "column": "_col0",
            "substring": "bert-jan",
            "expected_rows": 3,
        },
    },
    {
        "id": 4,
        "level": "Intermediate",
        "title": "不正アクセスの検出",
        "description": "errorcodeが 'AccessDenied' または 'Client.UnauthorizedOperation' のイベントは何件あるか？件数を求めよ。",
        "hint": "SELECT COUNT(*) FROM cloudtrail_logs WHERE errorcode IN ('AccessDenied', 'Client.UnauthorizedOperation')",
        "validate": {"type": "scalar", "value": 60},
    },
    {
        "id": 5,
        "level": "Intermediate",
        "title": "権限昇格の検出",
        "description": "IAMポリシーの変更（PutRolePolicy, AttachRolePolicy）イベントを全て取得し、時系列で並べよ。実行者と変更内容を確認せよ。",
        "hint": "WHERE eventname IN ('PutRolePolicy', 'AttachRolePolicy') ORDER BY eventtime",
        "validate": {
            "type": "row_range", "min": 11, "max": 15,
            "must_contain": {"column": "eventname", "values": ["PutRolePolicy", "AttachRolePolicy"]},
        },
    },
    {
        "id": 6,
        "level": "Advanced",
        "title": "証拠隠滅の試み",
        "description": "攻撃者がCloudTrailの証跡を無効化・削除しようとした痕跡を見つけよ（DeleteTrail, StopLogging）。成功と失敗を区別せよ。",
        "hint": "WHERE eventname IN ('DeleteTrail', 'StopLogging') — errorcodeカラムで成否を判定",
        "validate": {
            "type": "contains_only",
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
        "validate": {
            "type": "row_range", "min": 8, "max": 12,
            "must_contain": {"column": "eventname", "values": ["CreateUser", "CreateAccessKey", "CreateLoginProfile"]},
        },
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
                host=TRINO_HOST, port=TRINO_PORT, user="admin", catalog=CATALOG
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
    if not _ready.is_set():
        return {"error": "Trino 初期化中です。しばらくお待ちください。", "rows": [], "columns": []}
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(sql)
        columns = [desc[0] for desc in cur.description]
        rows = [[str(v) if v is not None else "NULL" for v in row] for row in cur.fetchall()]
        cur.close()
        conn.close()
        return {"columns": columns, "rows": rows, "error": None}
    except Exception as e:
        return {"error": str(e), "rows": [], "columns": []}


def _find_column(columns, name):
    lower_cols = [c.lower() for c in columns]
    target = name.lower()
    for i, c in enumerate(lower_cols):
        if c == target:
            return i
    if len(columns) == 1:
        return 0
    return -1


def _check_must_contain(v, rows, columns):
    mc = v.get("must_contain")
    if not mc:
        return True, ""
    col_idx = _find_column(columns, mc["column"])
    if col_idx == -1:
        return False, f"カラム '{mc['column']}' が結果に含まれていません。eventname等を含むSELECTにしてください。"
    found = set()
    for r in rows:
        val = r[col_idx]
        if val in mc["values"]:
            found.add(val)
        elif val not in mc["values"]:
            return False, f"対象外のイベント '{val}' が含まれています。結果を絞り込んでください。"
    missing = set(mc["values"]) - found
    if missing:
        return False, "必要なイベントが一部含まれていません。条件を確認してください。"
    return True, ""


def validate_result(quiz, result, sql=""):
    if result.get("error"):
        return False, "クエリでエラーが発生しました。"

    ok, msg = _check_sql_structure(sql)
    if not ok:
        return False, msg

    v = quiz["validate"]
    rows = result["rows"]
    columns = result["columns"]

    if v["type"] == "scalar":
        ok, msg = _check_scalar_sql(sql)
        if not ok:
            return False, msg
        if not rows or not rows[0]:
            return False, "結果が空です。COUNT等の集約関数を使ってください。"
        try:
            actual = int(rows[0][0])
        except (ValueError, IndexError):
            return False, f"数値が期待されていますが、結果は '{rows[0][0]}' です。COUNT(*)等を使ってください。"
        if actual == v["value"]:
            return True, f"正解！ {actual} 件です。"
        return False, f"不正解です。結果: {actual} 件"

    if v["type"] == "all_match":
        col_idx = _find_column(columns, v["column"])
        if col_idx == -1:
            return False, f"カラム '{v['column']}' が結果に含まれていません。"
        if not rows:
            return False, "結果が0行です。"
        mismatches = [r for r in rows if r[col_idx] != v["value"]]
        if mismatches:
            return False, f"{len(mismatches)} 行が期待値と一致しません。"
        return True, f"正解！ 全 {len(rows)} 行が一致しています。"

    if v["type"] == "row_range":
        lo, hi = v["min"], v["max"]
        ok, msg = _check_must_contain(v, rows, columns)
        if not ok:
            return False, msg
        if lo <= len(rows) <= hi:
            return True, f"正解！ {len(rows)} 行見つかりました。"
        return False, f"不正解です。結果: {len(rows)} 行"

    if v["type"] == "contains_value":
        col_idx = _find_column(columns, v["column"])
        if col_idx == -1:
            return False, f"カラム '{v['column']}' が結果に含まれていません。"
        expected_rows = v.get("expected_rows")
        if expected_rows and len(rows) != expected_rows:
            return False, f"不正解です。結果: {len(rows)} 行"
        if expected_rows:
            values = [r[col_idx] for r in rows]
            if len(set(values)) != len(values):
                return False, "重複した値があります。DISTINCT を使ってユニークな一覧を取得してください。"
        matches = [r for r in rows if v["substring"] in r[col_idx]]
        if not matches:
            return False, "期待される値が結果に含まれていません。"
        return True, f"正解！ {len(rows)} 件のユニークな値が見つかりました。"

    if v["type"] == "contains_only":
        col_idx = _find_column(columns, v["column"])
        if col_idx == -1:
            return False, f"カラム '{v['column']}' が結果に含まれていません。"
        if not rows:
            return False, "結果が0行です。"
        found = set()
        for r in rows:
            val = r[col_idx]
            if val not in v["substrings"]:
                return False, f"対象外のイベント '{val}' が含まれています。結果を絞り込んでください。"
            found.add(val)
        if len(found) < len(v["substrings"]):
            missing = set(v["substrings"]) - found
            return False, f"未検出: {', '.join(sorted(missing))}"
        return True, f"正解！ 検出: {', '.join(sorted(found))}（{len(rows)} 件）"

    return False, "不明な検証タイプです。"


@app.route("/")
def index():
    safe_quizzes = [
        {k: v for k, v in q.items() if k != "validate"} for q in QUIZZES
    ]
    return render_template("index.html", quizzes=safe_quizzes)


@app.route("/explore")
def explore():
    return render_template("explore.html")


@app.route("/api/explore", methods=["POST"])
def api_explore():
    body = request.json or {}
    query = body.get("query", "").strip()
    time_from = body.get("from", "")
    time_to = body.get("to", "")
    size = max(1, min(int(body.get("size", 500)), 5000))
    sort_field = body.get("sort_field", "eventtime")
    sort_order = body.get("sort_order", "DESC")

    if sort_order not in ("ASC", "DESC"):
        sort_order = "DESC"
    allowed_sort = {
        "eventtime", "eventsource", "eventname", "awsregion",
        "sourceipaddress", "errorcode",
    }
    if sort_field not in allowed_sort:
        sort_field = "eventtime"

    conditions = []
    if time_from:
        if not _ISO_TS_RE.match(time_from):
            return jsonify({"error": "Invalid 'from' format"}), 400
        conditions.append(f"eventtime >= '{time_from}'")
    if time_to:
        if not _ISO_TS_RE.match(time_to):
            return jsonify({"error": "Invalid 'to' format"}), 400
        conditions.append(f"eventtime <= '{time_to}'")
    if query:
        terms = [t.strip() for t in query.split(" AND ") if t.strip()]
        for term in terms:
            if ":" in term:
                field, value = term.split(":", 1)
                field = field.strip().lower()
                value = value.strip().strip('"').strip("'")
                safe_cols = {
                    "eventsource", "eventname", "awsregion", "sourceipaddress",
                    "useragent", "errorcode", "errormessage", "useridentity",
                    "requestparameters", "responseelements", "eventtype",
                    "readonly", "recipientaccountid", "eventid",
                }
                if field in safe_cols:
                    escaped = value.replace("'", "''")
                    if "*" in value:
                        like_val = escaped.replace("%", "\\%").replace("_", "\\_").replace("*", "%")
                        conditions.append(f"{field} LIKE '{like_val}' ESCAPE '\\'")
                    else:
                        conditions.append(f"{field} = '{escaped}'")
            elif term.startswith("NOT "):
                rest = term[4:].strip()
                escaped = rest.replace("'", "''").replace("%", "\\%").replace("_", "\\_")
                conditions.append(
                    f"CONCAT(COALESCE(eventsource,''), ' ', COALESCE(eventname,''), ' ', "
                    f"COALESCE(errorcode,''), ' ', COALESCE(sourceipaddress,''), ' ', "
                    f"COALESCE(useragent,'')) NOT LIKE '%{escaped}%' ESCAPE '\\'"
                )
            else:
                escaped = term.replace("'", "''").replace("%", "\\%").replace("_", "\\_")
                conditions.append(
                    f"CONCAT(COALESCE(eventsource,''), ' ', COALESCE(eventname,''), ' ', "
                    f"COALESCE(errorcode,''), ' ', COALESCE(sourceipaddress,''), ' ', "
                    f"COALESCE(useragent,'')) LIKE '%{escaped}%' ESCAPE '\\'"
                )

    where = " AND ".join(conditions) if conditions else "1=1"

    count_sql = f"SELECT COUNT(*) FROM cloudtrail_logs WHERE {where}"
    count_result = execute_query(count_sql)
    total = int(count_result["rows"][0][0]) if count_result["rows"] else 0

    data_sql = (
        f"SELECT * FROM cloudtrail_logs WHERE {where} "
        f"ORDER BY {sort_field} {sort_order} LIMIT {size}"
    )
    result = execute_query(data_sql)

    return jsonify({
        "total": total,
        "columns": result.get("columns", []),
        "rows": result.get("rows", []),
        "error": result.get("error"),
    })


HISTOGRAM_INTERVALS = {
    "5s":  {"expr": "CONCAT(SUBSTR(eventtime, 1, 17), "
            "LPAD(CAST(CAST(SUBSTR(eventtime, 18, 2) AS INTEGER) / 5 * 5 AS VARCHAR), 2, '0'))"},
    "15s": {"expr": "CONCAT(SUBSTR(eventtime, 1, 17), "
            "LPAD(CAST(CAST(SUBSTR(eventtime, 18, 2) AS INTEGER) / 15 * 15 AS VARCHAR), 2, '0'))"},
    "30s": {"expr": "CONCAT(SUBSTR(eventtime, 1, 17), "
            "LPAD(CAST(CAST(SUBSTR(eventtime, 18, 2) AS INTEGER) / 30 * 30 AS VARCHAR), 2, '0'))"},
    "1m":  {"expr": "SUBSTR(eventtime, 1, 16)"},
}


def _auto_interval(time_from, time_to):
    from datetime import datetime
    try:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        t0 = datetime.strptime(time_from, fmt)
        t1 = datetime.strptime(time_to, fmt)
        span = (t1 - t0).total_seconds()
    except (ValueError, TypeError):
        return "5s"
    if span <= 600:
        return "5s"
    if span <= 1800:
        return "15s"
    if span <= 3600:
        return "30s"
    return "1m"


@app.route("/api/histogram", methods=["POST"])
def api_histogram():
    body = request.json or {}
    query_str = body.get("query", "").strip()
    time_from = body.get("from", "")
    time_to = body.get("to", "")
    interval = body.get("interval", "auto")

    if interval == "auto":
        interval = _auto_interval(time_from, time_to)
    if interval not in HISTOGRAM_INTERVALS:
        interval = "1m"

    bucket_expr = HISTOGRAM_INTERVALS[interval]["expr"]

    conditions = []
    if time_from:
        if not _ISO_TS_RE.match(time_from):
            return jsonify({"error": "Invalid 'from' format"}), 400
        conditions.append(f"eventtime >= '{time_from}'")
    if time_to:
        if not _ISO_TS_RE.match(time_to):
            return jsonify({"error": "Invalid 'to' format"}), 400
        conditions.append(f"eventtime <= '{time_to}'")
    if query_str:
        escaped = query_str.replace("'", "''").replace("%", "\\%").replace("_", "\\_")
        conditions.append(
            f"CONCAT(COALESCE(eventsource,''), ' ', COALESCE(eventname,''), ' ', "
            f"COALESCE(errorcode,''), ' ', COALESCE(sourceipaddress,'')) "
            f"LIKE '%{escaped}%' ESCAPE '\\'"
        )

    where = " AND ".join(conditions) if conditions else "1=1"

    sql = (
        f"SELECT {bucket_expr} AS bucket, COUNT(*) AS cnt "
        f"FROM cloudtrail_logs WHERE {where} "
        f"GROUP BY {bucket_expr} ORDER BY bucket"
    )
    result = execute_query(sql)
    buckets = [{"key": r[0], "count": int(r[1])} for r in result.get("rows", [])]
    return jsonify({"buckets": buckets, "interval": interval, "error": result.get("error")})


@app.route("/api/field_stats", methods=["POST"])
def api_field_stats():
    body = request.json or {}
    field = body.get("field", "eventsource")
    time_from = body.get("from", "")
    time_to = body.get("to", "")

    safe_cols = {
        "eventsource", "eventname", "awsregion", "sourceipaddress",
        "useragent", "errorcode", "errormessage", "eventtype",
        "readonly", "recipientaccountid",
    }
    if field not in safe_cols:
        return jsonify({"error": "Invalid field"}), 400

    conditions = []
    if time_from:
        if not _ISO_TS_RE.match(time_from):
            return jsonify({"error": "Invalid 'from' format"}), 400
        conditions.append(f"eventtime >= '{time_from}'")
    if time_to:
        if not _ISO_TS_RE.match(time_to):
            return jsonify({"error": "Invalid 'to' format"}), 400
        conditions.append(f"eventtime <= '{time_to}'")

    where = " AND ".join(conditions) if conditions else "1=1"

    sql = (
        f"SELECT {field}, COUNT(*) AS cnt FROM cloudtrail_logs "
        f"WHERE {where} AND {field} IS NOT NULL AND {field} != '' "
        f"GROUP BY {field} ORDER BY cnt DESC LIMIT 20"
    )
    result = execute_query(sql)
    values = [{"value": r[0], "count": int(r[1])} for r in result.get("rows", [])]
    return jsonify({"field": field, "values": values, "error": result.get("error")})


@app.route("/api/health")
def health():
    if _ready.is_set():
        return jsonify({"status": "ready"})
    return jsonify({"status": "initializing"}), 503


@app.route("/api/query", methods=["POST"])
def api_query():
    body = request.json
    if not body or not isinstance(body, dict):
        return jsonify({"error": "不正なリクエストです"}), 400
    sql = body.get("sql", "").strip()
    if not sql:
        return jsonify({"error": "クエリが空です"}), 400
    stripped = _strip_sql(sql)
    if not re.match(r"^\s*SELECT\b", stripped, re.IGNORECASE):
        return jsonify({"error": "SELECTクエリのみ実行可能です"}), 400

    result = execute_query(sql)
    return jsonify(result)


@app.route("/api/validate", methods=["POST"])
def api_validate():
    body = request.json
    if not body or not isinstance(body, dict):
        return jsonify({"error": "不正なリクエストです"}), 400
    quiz_id = body.get("quiz_id")
    sql = body.get("sql", "").strip()

    quiz = next((q for q in QUIZZES if q["id"] == quiz_id), None)
    if not quiz:
        return jsonify({"error": "不明なクイズです"}), 404

    result = execute_query(sql)
    if result.get("error"):
        telemetry.quiz_attempt(quiz, False, sql)
        return jsonify({"correct": False, "message": result["error"], "result": result})

    correct, message = validate_result(quiz, result, sql)
    telemetry.quiz_attempt(quiz, correct, sql)
    return jsonify({"correct": correct, "message": message, "result": result})


if __name__ == "__main__":
    threading.Thread(target=init_all, daemon=True).start()
    telemetry.app_start()
    app.run(host="0.0.0.0", port=3000, debug=False)
