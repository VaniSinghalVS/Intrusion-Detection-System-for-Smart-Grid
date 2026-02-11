import json, time, random
from datetime import datetime, timezone

fname = "intrusion_log.txt"   # default used by app.py; change in sidebar if you want a different name

attacks = [
    ("DoS", "medium"),
    ("Replay", "low"),
    ("FalseDataInjection", "high"),
    ("UnauthorizedCommand", "medium")
]
sources = ["meter-01", "meter-02", "rtu-23", "sensor-5"]
dests = ["ctrl-1", "scada-2", "gateway-01"]

def now_iso():
    return datetime.now(timezone.utc).isoformat()  # e.g. 2025-11-09T10:00:00+00:00

print("Writing simulated alerts to", fname)
with open(fname, "a", encoding="utf-8") as f:
    for i in range(200):               # adjust number of lines as needed
        a, sev = random.choice(attacks)
        entry = {
            "ts": now_iso(),
            "src": random.choice(sources),
            "dst": random.choice(dests),
            "attack": a,
            "severity": sev,
            "details": f"simulated event #{i}",
            "role_src": "meter" if "meter" in random.choice(sources) else "edge",
            "role_dst": "control"
        }
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        time.sleep(0.05)   # ~20 events per second; increase/decrease as desired
print("Simulation complete.")
