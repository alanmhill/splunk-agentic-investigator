# agent/app/triage_loop.py
"""
SOC Triage Loop
- Loads detection pack YAML
- Renders SPL for each detection
- Executes via Splunk REST
- Scores + emits notables (placeholder here; Step 4+ will refine)

For now:
- Runs detections every N seconds
- Prints structured findings
- (Optional) sends notables to Splunk via HEC (stub)

Env:
  SPLUNK_BASE_URL=https://splunk:8089
  SPLUNK_USERNAME=admin
  SPLUNK_PASSWORD=changeme
  SPLUNK_VERIFY_SSL=false

  DETECTION_PACK_PATH=detections/winsec_triage_pack.yml
  TRIAGE_INTERVAL_SECONDS=60
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List

from query_renderer import QueryRenderer, DetectionPackError
from splunk_client import SplunkClient, SplunkClientError


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v.strip())
    except ValueError:
        return default


def run_once(qr: QueryRenderer, splunk: SplunkClient) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for det in qr.list_detections():
        try:
            spl, ctx = qr.render(det.id)
            results = splunk.run_search(spl, wait_timeout=30.0, poll_interval=0.5, results_count=200)

            if results:
                findings.append(
                    {
                        "detection_id": det.id,
                        "detection_name": det.name,
                        "category": det.category,
                        "severity_default": det.severity_default,
                        "intent": det.intent,
                        "render_ctx": ctx,
                        "result_count": len(results),
                        "results": results,
                    }
                )

        except (DetectionPackError, SplunkClientError) as e:
            findings.append(
                {
                    "detection_id": det.id,
                    "error": str(e),
                }
            )

    return findings


def main():
    pack_path = os.getenv("DETECTION_PACK_PATH", "detections/winsec_triage_pack.yml")
    interval = _env_int("TRIAGE_INTERVAL_SECONDS", 60)

    qr = QueryRenderer(pack_path)
    splunk = SplunkClient.from_env()

    print(f"[triage_loop] Loaded pack: {pack_path}")
    print(f"[triage_loop] Interval: {interval}s")
    print(f"[triage_loop] Detections: {[d.id for d in qr.list_detections()]}")

    while True:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[triage_loop] Run @ {ts}")

        findings = run_once(qr, splunk)

        # For now: print summary
        for f in findings:
            if "error" in f:
                print(f"  - {f['detection_id']}: ERROR: {f['error']}")
                continue

            print(
                f"  - {f['detection_id']} ({f['severity_default']}): "
                f"{f['result_count']} hit(s)"
            )

        # TODO Step 4: scoring + HEC emission to soc_notables
        time.sleep(interval)


if __name__ == "__main__":
    main()