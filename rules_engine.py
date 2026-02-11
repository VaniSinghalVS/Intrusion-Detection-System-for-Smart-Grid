# rules_engine.py
from collections import deque
import hashlib, time

# --- existing simple rules (keep if you want) ---
def detect_dos(features):         # SYN flood
    return features.get("syn_count", 0) > 50

def detect_icmp_flood(features):  # ping flood
    return features.get("icmp_req", 0) > 60

def detect_portscan(features):    # many distinct ports in window
    return len(features.get("dst_ports", [])) > 20

# --- replay detection (payload-hash approach) ---
_replay_store = {}  # mapping (src,dst) -> deque of (hash, ts)

def detect_replay(feature, payload_bytes=None, window_s=60, max_records=50):
    """
    Returns True if same payload repeated >=3 times within the window.
    payload_bytes: optional raw payload; if None uses 'details' field.
    """
    src = feature.get("src")
    dst = feature.get("dst")
    if not src or not dst:
        return False

    key = (src, dst)
    b = payload_bytes or str(feature.get("details","")).encode("utf-8")
    h = hashlib.sha256(b).hexdigest()

    dq = _replay_store.setdefault(key, deque(maxlen=max_records))
    now = time.time()

    # remove old records
    while dq and (now - dq[0][1]) > window_s:
        dq.popleft()

    same = sum(1 for hh, ts in dq if hh == h)
    dq.append((h, now))

    # threshold: repeated identical payload 3+ times in window -> suspect replay
    return (same + 1) >= 3

# --- unauthorized command detection (simple whitelist) ---
def detect_unauth_command(feature, roles_map, whitelist):
    """
    Returns True if a sensitive command was sent by a non-whitelisted source.
    Expects:
      - feature may contain 'command' or 'cmd' string
      - roles_map is dict {ip: role}
      - whitelist is dict containing 'control_commands_from' list and 'sensitive_commands' list
    """
    src = feature.get("src")
    if not src:
        return False

    cmd = (feature.get("cmd") or feature.get("command") or "").strip()
    if not cmd:
        return False

    # normalize
    cmd_up = cmd.upper()
    allowed_from = set(whitelist.get("control_commands_from", []))
    sensitive = set(c.upper() for c in whitelist.get("sensitive_commands", []))

    # if command is sensitive and source not in allowed list => unauthorized
    if cmd_up in sensitive and src not in allowed_from:
        return True

    # role-based allowed command types (optional)
    allowed_types = whitelist.get("allowed_command_types", {})
    role = roles_map.get(src, "unknown")
    allowed_for_role = [c.upper() for c in allowed_types.get(role, [])]
    if allowed_for_role and cmd_up not in allowed_for_role:
        return True

    return False
