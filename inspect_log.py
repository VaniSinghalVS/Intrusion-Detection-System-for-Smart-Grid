import json
from datetime import datetime
from pathlib import Path

p = Path("intrusion_log.txt")
print("Full path:", p.resolve())
print("File exists:", p.exists())
print("File size (bytes):", p.stat().st_size if p.exists() else "missing")

total = valid_json = valid_with_ts = 0
bad_samples = []
ts_min = ts_max = None

with p.open(encoding="utf-8", errors="ignore") as f:
    for ln in f:
        total += 1
        s = ln.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
            valid_json += 1
            ts = obj.get("ts")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    valid_with_ts += 1
                    if ts_min is None or dt < ts_min: ts_min = dt
                    if ts_max is None or dt > ts_max: ts_max = dt
                except Exception:
                    if len(bad_samples) < 5: bad_samples.append(("bad-ts", s[:180]))
            else:
                if len(bad_samples) < 5: bad_samples.append(("no-ts", s[:180]))
        except Exception:
            if len(bad_samples) < 5: bad_samples.append(("bad-json", s[:180]))

print("Total lines:", total)
print("Valid JSON lines:", valid_json)
print("Valid JSON with parsable ts:", valid_with_ts)
print("ts min:", ts_min, " ts max:", ts_max)
print("Sample bad lines (up to 5):")
for t, s in bad_samples:
    print(" -", t, ":", s)
