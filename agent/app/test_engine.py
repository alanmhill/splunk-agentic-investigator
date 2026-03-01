from detection_engine import DetectionEngine

engine = DetectionEngine("detections/winsec_triage_pack.yml")

results = engine.run_all()

for r in results:
    print("=" * 50)
    print("Detection:", r["detection_id"])
    print("Results:", r["result_count"])