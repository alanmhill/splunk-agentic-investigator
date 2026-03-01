# agent/app/splunk_client.py
"""
Splunk REST API execution client (search/jobs + polling + JSON results)

This is designed for your SOC triage loop:
- Create a search job
- Poll until done (or timeout)
- Fetch results as JSON
- Return list[dict]

Auth options:
1) Basic auth (Splunk username/password)
2) Splunk token (session or bearer) — optional

ENV VARS (recommended):
  SPLUNK_BASE_URL=https://splunk:8089
  SPLUNK_USERNAME=admin
  SPLUNK_PASSWORD=changeme
  SPLUNK_VERIFY_SSL=false   (true/false)

Notes:
- Splunk management port is 8089 (REST API), NOT HEC 8088.
- You can keep VERIFY off in local dev, but turn on for real deployments.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


class SplunkClientError(Exception):
    pass


def _env_bool(name: str, default: bool = True) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass
class SplunkClientConfig:
    base_url: str  # e.g., https://splunk:8089
    username: Optional[str] = None
    password: Optional[str] = None
    bearer_token: Optional[str] = None  # optional alternative to basic auth
    verify_ssl: bool = True
    app: str = "search"  # namespace for searches, usually "search"
    owner: str = "nobody"  # "admin" also works; "nobody" is common
    timeout_seconds: int = 30


class SplunkClient:
    def __init__(self, cfg: SplunkClientConfig):
        self.cfg = cfg
        self.session = requests.Session()

        if not self.cfg.base_url:
            raise SplunkClientError("Splunk base_url is required (e.g., https://splunk:8089).")

        # Normalize base URL (no trailing slash)
        self.cfg.base_url = self.cfg.base_url.rstrip("/")

        # Auth setup
        if cfg.bearer_token:
            self.session.headers.update({"Authorization": f"Bearer {cfg.bearer_token}"})
        elif cfg.username and cfg.password:
            self.session.auth = (cfg.username, cfg.password)
        else:
            raise SplunkClientError("Provide either bearer_token OR username+password for Splunk REST API auth.")

        # Splunk likes this for JSON
        self.session.headers.update({"Accept": "application/json"})

    @classmethod
    def from_env(cls) -> "SplunkClient":
        base_url = os.getenv("SPLUNK_BASE_URL", "https://splunk:8089")
        username = os.getenv("SPLUNK_USERNAME")
        password = os.getenv("SPLUNK_PASSWORD")
        token = os.getenv("SPLUNK_BEARER_TOKEN")
        verify_ssl = _env_bool("SPLUNK_VERIFY_SSL", default=True)

        cfg = SplunkClientConfig(
            base_url=base_url,
            username=username,
            password=password,
            bearer_token=token,
            verify_ssl=verify_ssl,
        )
        return cls(cfg)

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.cfg.base_url + path

    def create_search_job(
        self,
        spl: str,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        exec_mode: str = "normal",
        max_time: int = 60,
    ) -> str:
        """
        Creates a search job and returns the SID.
        Uses: POST /servicesNS/{owner}/{app}/search/jobs
        """
        if not spl.strip().startswith("search"):
            # Splunk allows bare SPL, but prefixing is fine; we won't force it.
            pass

        path = f"/servicesNS/{self.cfg.owner}/{self.cfg.app}/search/jobs"
        data = {
            "search": spl,
            "output_mode": "json",
            "exec_mode": exec_mode,  # "normal" or "blocking"
            "max_time": str(max_time),
        }
        if earliest:
            data["earliest_time"] = earliest
        if latest:
            data["latest_time"] = latest

        r = self.session.post(
            self._url(path),
            data=data,
            verify=self.cfg.verify_ssl,
            timeout=self.cfg.timeout_seconds,
        )
        if r.status_code >= 400:
            raise SplunkClientError(f"Failed to create search job ({r.status_code}): {r.text}")

        payload = r.json()
        # Splunk returns sid under payload['sid'] or payload['entry'][0]['content']['sid'] in some formats.
        sid = payload.get("sid")
        if not sid:
            # try alternate shape
            try:
                sid = payload["entry"][0]["content"]["sid"]
            except Exception:
                sid = None

        if not sid:
            raise SplunkClientError(f"Could not parse SID from Splunk response: {payload}")

        return sid

    def get_job(self, sid: str) -> Dict[str, Any]:
        """
        Gets job status/metadata.
        GET /services/search/jobs/{sid}?output_mode=json
        """
        path = f"/services/search/jobs/{sid}"
        r = self.session.get(
            self._url(path),
            params={"output_mode": "json"},
            verify=self.cfg.verify_ssl,
            timeout=self.cfg.timeout_seconds,
        )
        if r.status_code >= 400:
            raise SplunkClientError(f"Failed to get job ({r.status_code}): {r.text}")
        return r.json()

    def wait_for_done(
        self,
        sid: str,
        poll_interval: float = 0.5,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Polls until dispatchState= DONE (or timeout). Returns final job payload.
        """
        start = time.time()
        last_payload: Dict[str, Any] = {}

        while True:
            last_payload = self.get_job(sid)
            try:
                content = last_payload["entry"][0]["content"]
                state = content.get("dispatchState") or content.get("dispatch_state")
                is_done = state == "DONE"
            except Exception:
                # fallback: attempt best effort
                is_done = False

            if is_done:
                return last_payload

            if time.time() - start > timeout:
                raise SplunkClientError(f"Timed out waiting for search job {sid} to complete.")

            time.sleep(poll_interval)

    def get_results(
        self,
        sid: str,
        count: int = 200,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Fetches results for a completed job.
        GET /services/search/jobs/{sid}/results?output_mode=json
        """
        path = f"/services/search/jobs/{sid}/results"
        r = self.session.get(
            self._url(path),
            params={"output_mode": "json", "count": count, "offset": offset},
            verify=self.cfg.verify_ssl,
            timeout=self.cfg.timeout_seconds,
        )
        if r.status_code >= 400:
            raise SplunkClientError(f"Failed to fetch results ({r.status_code}): {r.text}")

        payload = r.json()
        results = payload.get("results", [])
        if not isinstance(results, list):
            raise SplunkClientError(f"Unexpected results format: {payload}")
        return results

    def run_search(
        self,
        spl: str,
        wait_timeout: float = 30.0,
        poll_interval: float = 0.5,
        results_count: int = 200,
    ) -> List[Dict[str, Any]]:
        """
        Convenience: create job -> wait -> results.
        """
        sid = self.create_search_job(spl)
        self.wait_for_done(sid, poll_interval=poll_interval, timeout=wait_timeout)
        return self.get_results(sid, count=results_count)

    def delete_job(self, sid: str) -> None:
        """
        Deletes job to reduce clutter.
        DELETE /services/search/jobs/{sid}
        """
        path = f"/services/search/jobs/{sid}"
        r = self.session.delete(
            self._url(path),
            params={"output_mode": "json"},
            verify=self.cfg.verify_ssl,
            timeout=self.cfg.timeout_seconds,
        )
        # Not fatal if delete fails; just log upstream if desired.
        if r.status_code >= 400:
            raise SplunkClientError(f"Failed to delete job ({r.status_code}): {r.text}")