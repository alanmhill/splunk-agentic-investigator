import importlib
import os
import time
from app.hec_client import SplunkHEC


def eps_value() -> int:
    try:
        return max(1, int(os.environ.get("EPS", "5")))
    except ValueError:
        return 5


def load_scenario(name: str):
    # scenarios are modules under /scenarios (copied into container)
    # e.g. scenarios/password_spray.py exposes generate()
    mod = importlib.import_module(f"scenarios.{name}")
    if not hasattr(mod, "generate"):
        raise RuntimeError(f"Scenario scenarios.{name} must define generate()")
    return mod.generate


def main():
    scenario = os.environ.get("SCENARIO", "password_spray")
    eps = eps_value()
    interval = 1.0 / float(eps)

    generate = load_scenario(scenario)
    hec = SplunkHEC()

    print(f"[eventgen] scenario={scenario} eps={eps} hec={os.environ.get('SPLUNK_HEC_URL')}")

    while True:
        ev = generate()
        host = ev.get("dest_host", "sim-host-01")
        ok = hec.send(ev, host=host, source="soc-sim")
        if not ok:
            print("[eventgen] failed to send event")
        time.sleep(interval)


if __name__ == "__main__":
    main()