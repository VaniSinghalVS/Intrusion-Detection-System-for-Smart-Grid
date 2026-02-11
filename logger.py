import json, time, os

_last_alert = {}

def _pair_key(a, b):
    if not a: a = ""
    if not b: b = ""
    try:
        return tuple(sorted((str(a), str(b))))
    except:
        return (str(a), str(b))

def write_alert(alert: dict, path="intrusion_log.txt", cooldown_s=30):
    now = time.time()
    src = alert.get("src", "")
    dst = alert.get("dst", "")
    pair = _pair_key(src, dst)
    key = (pair, alert.get("attack"))

    last_ts, last_digest = _last_alert.get(key, (0, None))

    try:
        details = alert.get("details", "")
        digest = str(hash(details))
    except Exception:
        digest = None

    if now - last_ts < cooldown_s:
        if digest is not None and digest != last_digest:
            pass
        else:
            return False

    _last_alert[key] = (now, digest)

    alert.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    folder = os.path.dirname(path)
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")
    return True
