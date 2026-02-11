# fusion.py

def decide_score(thr_flag, rules, ctx):
    """
    Combine results from rule-based detections and adaptive threshold.
    Returns a dictionary with attack name, severity, and optional score/details.
    """

    # 1. Aggregate rule triggers
    triggered = [name for name, flag in rules.items() if flag]

    # 2. If nothing triggered and no threshold anomaly, return None
    if not triggered and not thr_flag:
        return None

    # 3. Determine main attack type
    if "unauth_cmd" in triggered:
        attack = "Unauthorized Command"
        severity = "High"
    elif "replay" in triggered:
        attack = "Replay Attack"
        severity = "Medium"
    elif "icmp_flood" in triggered:
        attack = "ICMP Flood"
        severity = "High"
    elif "portscan" in triggered:
        attack = "Port Scan"
        severity = "Medium"
    elif "dos" in triggered or thr_flag:
        attack = "DoS Attack"
        severity = "High"
    else:
        attack = "Anomaly"
        severity = "Low"

    # 4. Adjust severity for context (optional)
    if ctx.get("role_src") == "control" and attack == "Unauthorized Command":
        severity = "Critical"
    if ctx.get("whitelisted"):
        severity = "Low"

    # 5. Build decision result
    return {
        "attack": attack,
        "severity": severity,
        "score": len(triggered),
        "details": f"Triggered: {', '.join(triggered)}"
    }
