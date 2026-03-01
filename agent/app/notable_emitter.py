"""
notable_emitter.py

Emit SOC notables back into Splunk via HEC.

Env vars expected (match your eventgen style):
  SPLUNK_HEC_URL=https://splunk:8088/services/collector
  SPLUNK_HEC_TOKEN=...
  SPLUNK_HEC_INSECURE=true|false

Defaults:
  index = soc_notables
  sourcetype = agent:notable
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
import urllib3


class NotableEmitterError(Exception):
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass
class NotableEmitterConfig:
    hec_url: str
    hec_token: str
    insecure: bool = False  # if true, do not verify TLS cert
    index: str = "soc_notables"
    sourcetype: str = "agent:notable"
    host: Optional[str] = None
    source: str = "soc-triage-pack"
    timeout_seconds: int = 10


class NotableEmitter:
    def __init__(self, cfg: NotableEmitterConfig):
        self.cfg = cfg

        if not self.cfg.hec_url or not self.cfg.hec_token:
            raise NotableEmitterError("HEC URL and HEC token are required.")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Splunk {self.cfg.hec_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        # If insecure, suppress warnings for local/dev
        if self.cfg.insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @classmethod
    def from_env(cls) -> "NotableEmitter":
        hec_url = os.getenv("SPLUNK_HEC_URL", "").rstrip("/")
        hec_token = os.getenv("SPLUNK_HEC_TOKEN", "")
        insecure = _env_bool("SPLUNK_HEC_INSECURE", default=False)

        index = os.getenv("SOC_NOTABLES_INDEX", "soc_notables")
        sourcetype = os.getenv("SOC_NOTABLES_SOURCETYPE", "agent:notable")
        host = os.getenv("SOC_NOTABLES_HOST")  # optional override
        source = os.getenv("SOC_NOTABLES_SOURCE", "soc-triage-pack")

        cfg = NotableEmitterConfig(
            hec_url=hec_url,
            hec_token=hec_token,
            insecure=insecure,
            index=index,
            sourcetype=sourcetype,
            host=host,
            source=source,
        )
        return cls(cfg)

    def emit(
        self,
        event: Dict[str, Any],
        *,
        time_epoch: Optional[float] = None,
        fields: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit a single notable event to Splunk HEC.

        event: the event payload (your notable content)
        time_epoch: optional epoch timestamp; defaults to now
        fields: optional HEC "fields" for indexed extractions (if configured)
        """
        t = time_epoch if time_epoch is not None else time.time()

        payload: Dict[str, Any] = {
            "time": t,
            "host": self.cfg.host or event.get("dest_host") or event.get("host") or "agent-api",
            "source": self.cfg.source,
            "sourcetype": self.cfg.sourcetype,
            "index": self.cfg.index,
            "event": event,
        }

        if fields:
            payload["fields"] = fields

        r = self.session.post(
            self.cfg.hec_url,
            json=payload,
            verify=not self.cfg.insecure,
            timeout=self.cfg.timeout_seconds,
        )

        if r.status_code not in (200, 201):
            raise NotableEmitterError(f"HEC emit failed ({r.status_code}): {r.text}")

        # Splunk HEC usually returns {"text":"Success","code":0}
        try:
            resp = r.json()
            if resp.get("code", 0) != 0:
                raise NotableEmitterError(f"HEC returned non-zero code: {resp}")
        except ValueError:
            # Non-JSON response is unusual but not always fatal; treat as error for strictness
            raise NotableEmitterError(f"HEC returned non-JSON response: {r.text}")