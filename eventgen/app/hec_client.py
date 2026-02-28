import json
import os
import time
import requests


class SplunkHEC:
    def __init__(self):
        self.url = os.environ.get("SPLUNK_HEC_URL", "").rstrip("/")
        self.token = os.environ.get("SPLUNK_HEC_TOKEN", "")
        self.index = os.environ.get("SPLUNK_INDEX", "soc_sim")
        self.sourcetype = os.environ.get("SPLUNK_SOURCETYPE", "winsec")

        if not self.url or not self.token:
            raise RuntimeError("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN must be set")

        self.headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        }

    def send(self, event: dict, host: str = "sim-host-01", source: str = "soc-sim") -> bool:
        payload = {
            "time": time.time(),
            "host": host,
            "source": source,
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": event,
        }

        backoff = 1.0
        for attempt in range(6):
            try:
                verify = os.environ.get("SPLUNK_HEC_INSECURE", "false").lower() not in ("1", "true", "yes")
                r = requests.post(self.url, headers=self.headers, data=json.dumps(payload), timeout=5, verify=verify)
                if r.status_code == 200:
                    return True
                print(f"[hec] status={r.status_code} body={r.text}")
            except Exception as e:
                print(f"[hec] attempt={attempt+1} error={e}")

            time.sleep(backoff)
            backoff = min(backoff * 2, 10.0)

        return False