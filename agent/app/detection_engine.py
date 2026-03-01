from typing import List, Dict, Any
from query_renderer import QueryRenderer
from splunk_client import SplunkClient


class DetectionEngine:
    def __init__(self, pack_path: str):
        self.renderer = QueryRenderer(pack_path)
        self.splunk = SplunkClient.from_env()

    def run_detection(self, detection_id: str, overrides: Dict[str, Any] = None) -> Dict[str, Any]:
        spl, ctx = self.renderer.render(detection_id, overrides=overrides)

        results = self.splunk.run_search(spl)

        return {
            "detection_id": detection_id,
            "spl": spl,
            "context": ctx,
            "result_count": len(results),
            "results": results,
        }

    def run_all(self) -> List[Dict[str, Any]]:
        findings = []

        for detection in self.renderer.list_detections():
            result = self.run_detection(detection.id)
            findings.append(result)

        return findings