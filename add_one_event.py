import json
from datetime import datetime, timezone

entry = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "src": "demo-meter",
    "dst": "ctrl-1",
    "attack": "ManualTest",
    "severity": "high",
    "details": "manual trigger",
    "role_src": "meter",
    "role_dst": "control"
}

with open("intrusion_log.txt", "a", encoding="utf-8") as f:
    f.write(json.dumps(entry, ensure_ascii=False) + "\n")

print("Added:", entry)
