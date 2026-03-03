import os, json, time, hashlib
from datetime import datetime, timezone
import requests
import psycopg2

SPLUNK_URL = os.getenv("SPLUNK_URL", "https://splunk:8089")
SPLUNK_USER = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASSWORD", "changeme")

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_DB = os.getenv("POSTGRES_DB", "agentic_secops")
PG_USER = os.getenv("POSTGRES_USER", "agent")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "agent")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "20"))
LOOKBACK = os.getenv("LOOKBACK", "-15m")
MAX_EVENTS = int(os.getenv("MAX_EVENTS", "300"))

# Key point: pull the whole raw notable + core fields.
# We will parse evidence[] in Python for reliability.
SEARCH = rf"""
search index=soc_notables earliest={LOOKBACK}
| spath
| eval detection_id=coalesce(detection_id, detection_id_s, detection, rule_id)
| eval detection_name=coalesce(detection_name, detection_name_s, rule_name)
| eval notable_time=_time
| table _time detection_id detection_name category severity risk_score result_count summary evidence _raw
| sort 0 - _time
| head {MAX_EVENTS}
"""

INSERT_NOTABLE_SQL = """
INSERT INTO soc_notables
(notable_time, detection_id, detection_name, category, severity, risk_score, result_count,
 src_ip, dest_host, users, metric_name, metric_value,
 payload, notable_key)
VALUES
(%(notable_time)s, %(detection_id)s, %(detection_name)s, %(category)s, %(severity)s, %(risk_score)s, %(result_count)s,
 %(src_ip)s, %(dest_host)s, %(users)s, %(metric_name)s, %(metric_value)s,
 %(payload)s::jsonb, %(notable_key)s)
ON CONFLICT (notable_key) DO NOTHING;
"""

INSERT_EVIDENCE_SQL = """
INSERT INTO soc_evidence
(notable_key, notable_time, detection_id, src_ip, dest_host, metric_name, metric_value, users, evidence_key)
VALUES
(%(notable_key)s, %(notable_time)s, %(detection_id)s, %(src_ip)s, %(dest_host)s, %(metric_name)s, %(metric_value)s, %(users)s::jsonb, %(evidence_key)s)
ON CONFLICT (evidence_key) DO NOTHING;
"""


def first(v):
    """Normalize Splunk multivalue/list fields to a single scalar."""
    if v is None:
        return None
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v


def sha256_text(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def to_timestamptz(v):
    v = first(v)
    if v is None:
        return None

    # 1) epoch seconds
    try:
        ts = float(v)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        pass

    s = str(v).strip()

    # 2) "YYYY-MM-DD HH:MM:SS.mmm GMT"
    # Example: "2026-03-03 02:04:27.105 GMT"
    try:
        if s.endswith(" GMT"):
            s2 = s[:-4]  # drop trailing " GMT"
            dt = datetime.strptime(s2, "%Y-%m-%d %H:%M:%S.%f")
            return dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass

    # 3) ISO 8601 variants
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def safe_int(v):
    try:
        if v is None:
            return None
        return int(float(str(v)))
    except Exception:
        return None


def splunk_export(search: str) -> list[dict]:
    url = f"{SPLUNK_URL}/services/search/jobs/export"
    data = {"search": search.strip(), "output_mode": "json"}
    r = requests.post(url, data=data, auth=(SPLUNK_USER, SPLUNK_PASS), verify=False, timeout=60)
    r.raise_for_status()

    out = []
    for line in r.text.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("result"):
            out.append(obj["result"])
    return out


def parse_payload(ev: dict) -> dict:
    """
    The most reliable representation is the JSON in _raw.
    If _raw is JSON, load it. Otherwise fall back to the field dict.
    """
    raw = first(ev.get("_raw"))
    if isinstance(raw, str):
        raw_str = raw.strip()
        if raw_str.startswith("{") and raw_str.endswith("}"):
            try:
                return json.loads(raw_str)
            except Exception:
                pass
    # fallback: field dict itself
    return ev


def extract_evidence(payload: dict) -> list[dict]:
    ev = payload.get("evidence")
    if ev is None:
        return []
    # evidence might already be list[dict]
    if isinstance(ev, list):
        return [x for x in ev if isinstance(x, dict)]
    # sometimes it comes as stringified JSON
    if isinstance(ev, str):
        try:
            parsed = json.loads(ev)
            if isinstance(parsed, list):
                return [x for x in parsed if isinstance(x, dict)]
        except Exception:
            return []
    return []


def infer_metric_name_value(evidence_item: dict) -> tuple[str | None, int | None]:
    """
    Find a numeric metric field in the evidence item besides src_ip/dest_host/users.
    Example: rdp_failures=148, attempts=4216, etc.
    """
    ignore = {"src_ip", "dest_host", "users"}
    for k, v in evidence_item.items():
        if k in ignore:
            continue
        iv = safe_int(v)
        if iv is not None:
            return k, iv
    return None, None


def collect_users(evidence_items: list[dict]) -> list[str]:
    users = set()
    for item in evidence_items:
        u = item.get("users")
        if isinstance(u, list):
            for x in u:
                if x is not None:
                    users.add(str(x))
        elif isinstance(u, str) and u.strip():
            # sometimes a comma-separated string
            for x in u.split(","):
                x = x.strip()
                if x:
                    users.add(x)
    return sorted(users)


def main():
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS
    )
    conn.autocommit = True

    print("Starting soc_notables ingest loop...")
    print(f"Splunk={SPLUNK_URL} lookback={LOOKBACK} poll={POLL_SECONDS}s max={MAX_EVENTS}")
    print(f"Postgres={PG_HOST}:{PG_PORT}/{PG_DB} user={PG_USER}")

    while True:
        try:
            results = splunk_export(SEARCH)
            print(f"Fetched {len(results)} rows from Splunk")

            inserted_notables = 0
            inserted_evidence = 0

            with conn.cursor() as cur:
                for row in results:
                    t_raw = row.get("_time") or row.get("notable_time") or payload.get("_time") or payload.get("notable_time")
                    notable_time = to_timestamptz(t_raw)

                    # Build payload from _raw JSON
                    payload = parse_payload(row)

                    detection_id = payload.get("detection_id") or first(row.get("detection_id"))
                    detection_name = payload.get("detection_name") or first(row.get("detection_name"))
                    category = payload.get("category") or first(row.get("category"))
                    severity = payload.get("severity") or first(row.get("severity"))
                    risk_score = safe_int(payload.get("risk_score") or first(row.get("risk_score")))
                    result_count = safe_int(payload.get("result_count") or first(row.get("result_count")))

                    evidence_items = extract_evidence(payload)

                    # Pick first src_ip/dest_host seen in evidence (best effort)
                    src_ip = None
                    dest_host = None
                    metric_name = None
                    metric_value = None

                    if evidence_items:
                        for item in evidence_items:
                            if src_ip is None and item.get("src_ip"):
                                src_ip = str(item.get("src_ip"))
                            if dest_host is None and item.get("dest_host"):
                                dest_host = str(item.get("dest_host"))
                            if metric_name is None or metric_value is None:
                                mn, mv = infer_metric_name_value(item)
                                if mn and mv is not None:
                                    metric_name, metric_value = mn, mv

                    users_list = collect_users(evidence_items)
                    users_csv = ",".join(users_list) if users_list else None

                    # Idempotency: include time + detection + stable signature
                    notable_key = sha256_text(
                        f"{t_raw or ''}|{detection_id or ''}|{src_ip or ''}|{dest_host or ''}"
                    )

                    if notable_time is None:
                        print("WARN: skipping event with no parseable time. _time=", t_raw)
                        continue

                    notable_insert = {
                        "notable_time": notable_time,
                        "detection_id": detection_id,
                        "detection_name": detection_name,
                        "category": category,
                        "severity": severity,
                        "risk_score": risk_score,
                        "result_count": result_count,
                        "src_ip": src_ip,
                        "dest_host": dest_host,
                        "users": users_csv,
                        "metric_name": metric_name,
                        "metric_value": metric_value,
                        "payload": json.dumps(payload),
                        "notable_key": notable_key,
                    }

                    cur.execute(INSERT_NOTABLE_SQL, notable_insert)
                    if cur.rowcount == 1:
                        inserted_notables += 1

                    # Evidence rows (optional but excellent for Grafana)
                    for item in evidence_items:
                        e_src = item.get("src_ip")
                        e_dst = item.get("dest_host")
                        mn, mv = infer_metric_name_value(item)

                        e_users = item.get("users")
                        if e_users is None:
                            e_users = []

                        evidence_key = sha256_text(
                            f"{notable_key}|{str(e_src or '')}|{str(e_dst or '')}"
                        )

                        evidence_insert = {
                            "notable_key": notable_key,
                            "notable_time": notable_time,
                            "detection_id": detection_id,
                            "src_ip": str(e_src) if e_src is not None else None,
                            "dest_host": str(e_dst) if e_dst is not None else None,
                            "metric_name": mn,
                            "metric_value": mv,
                            "users": json.dumps(e_users),
                            "evidence_key": evidence_key,
                        }

                        # If you didn't create soc_evidence table, this will fail—comment out if needed.
                        cur.execute(INSERT_EVIDENCE_SQL, evidence_insert)
                        if cur.rowcount == 1:
                            inserted_evidence += 1

            print(f"Inserted notables: {inserted_notables}, inserted evidence rows: {inserted_evidence}")

        except Exception as e:
            print(f"[ERROR] ingest loop: {e}")

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()