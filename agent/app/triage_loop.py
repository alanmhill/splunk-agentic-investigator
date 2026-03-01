"""
triage_loop.py

Runs SOC Triage Pack continuously:
- Render SPL from detection pack
- Execute via Splunk REST
- Score findings
- Emit notables to Splunk via HEC (index=soc_notables)

Env:
  DETECTION_PACK_PATH=detections/winsec_triage_pack.yml
  TRIAGE_INTERVAL_SECONDS=60
  TRIAGE_EARLIEST=-15m (optional override)
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List

from app.query_renderer import QueryRenderer
from app.splunk_client import SplunkClient
from app.notable_emitter import NotableEmitter
from app.scoring import score_finding


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def build_summary(detection_id: str, rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return f"{detection_id} triggered"

    r0 = rows[0]
    src_ip = r0.get("src_ip")
    user = r0.get("user")
    dest_host = r0.get("dest_host")

    # Prefer these “metric fields” if present
    metric = (
        r0.get("attempts")
        or r0.get("rdp_failures")
        or r0.get("fails")
        or r0.get("unique_ports")
        or r0.get("unique_dests")
        or r0.get("count")
    )

    parts = [detection_id]
    if src_ip:
        parts.append(f"src_ip={src_ip}")
    if user:
        parts.append(f"user={user}")
    if dest_host:
        parts.append(f"dest_host={dest_host}")
    if metric is not None:
        parts.append(f"metric={metric}")

    return " | ".join(parts)


def main() -> None:
    pack_path = os.getenv("DETECTION_PACK_PATH", "detections/winsec_triage_pack.yml")
    interval = _env_int("TRIAGE_INTERVAL_SECONDS", 60)
    earliest_override = os.getenv("TRIAGE_EARLIEST")  # optional

    renderer = QueryRenderer(pack_path)
    splunk = SplunkClient.from_env()
    emitter = NotableEmitter.from_env()

    print(f"[triage_loop] pack={pack_path} interval={interval}s earliest_override={earliest_override}")

    while True:
        run_ts = time.time()

        for det_info in renderer.list_detections():
            det_def = renderer.get_detection(det_info.id)

            overrides: Dict[str, Any] = {}
            if earliest_override:
                overrides["earliest"] = earliest_override

            spl, ctx = renderer.render(det_info.id, overrides=overrides)

            rows = splunk.run_search(spl, wait_timeout=60.0, poll_interval=0.5, results_count=200)
            if not rows:
                continue

            risk_score, severity = score_finding(det_def, len(rows))
            summary = build_summary(det_info.id, rows)

            notable_event = {
                "detection_id": det_info.id,
                "detection_name": det_info.name,
                "category": det_info.category,
                "severity": severity,
                "risk_score": risk_score,
                "summary": summary,
                "result_count": len(rows),
                "time_window": {
                    "earliest": ctx.get("earliest"),
                    "latest": ctx.get("latest"),
                },
                # keep evidence small
                "evidence": rows[:5],
                "spl": spl,  # optional: include for transparency/debug
            }

            emitter.emit(notable_event)

            print(f"[triage_loop] emitted: {det_info.id} severity={severity} score={risk_score} rows={len(rows)}")

        # sleep remaining time
        elapsed = time.time() - run_ts
        sleep_for = max(1, interval - int(elapsed))
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()