import random
from datetime import datetime, timezone


def iso_now():
    return datetime.now(timezone.utc).isoformat()


def generate():
    # TEST-NET-3 example IP (safe/non-routable)
    src_ip = "203.0.113.50"

    users = ["ajones", "bsmith", "cwilson", "dlee", "ekhan", "fgarcia", "hpatel", "mroberts", "tnguyen"]
    user = random.choice(users)

    status = random.choice(["0xC000006D", "0xC000006A", "0xC0000234"])
    workstation = random.choice(["WS-044", "WS-118", "WS-203", "WS-077"])
    dest_host = random.choice(["DC-01", "DC-02"])

    return {
        "timestamp": iso_now(),
        "event_code": 4625,
        "event_name": "An account failed to log on",
        "logon_type": random.choice([2, 3, 10]),
        "user": user,
        "domain": "CORP",
        "src_ip": src_ip,
        "workstation": workstation,
        "dest_host": dest_host,
        "status": status,
        "process": random.choice(["winlogon.exe", "lsass.exe", "svchost.exe"]),
        "channel": "Security",
        "severity": "medium",
        "category": "authentication",
        "message": f"Failed logon for {user} from {src_ip} to {dest_host}",
    }