import time
from scapy.all import sniff
from thresholds import EWMA
from rules_engine import detect_dos, detect_icmp_flood, detect_portscan, detect_replay, detect_unauth_command
from preprocessor import features_from_packets
from roles_policies import load_policies, role_of, is_whitelisted
from logger import write_alert
from fusion import decide_score


WINDOW_S = 10
BPF = "tcp or icmp"   

ewma_by_src = {}

def process_window(pkts):
     for pkt in pkts:
        src = getattr(pkt, 'src', None)
        dst = getattr(pkt, 'dst', None)
        feat = {"src": src, "dst": dst, "details": str(pkt.summary())}
        roles, whitelist = load_policies()

        ew = ewma_by_src.setdefault(src, EWMA(alpha=0.3))
        thr_flag = ew.update_and_is_outlier(feat.get("syn_count", 0))

        rules = {
            "dos": detect_dos(feat),
            "icmp_flood": detect_icmp_flood(feat),
            "portscan": detect_portscan(feat),
            "replay": detect_replay(feat, payload_bytes=None, window_s=60),
            "unauth_cmd": detect_unauth_command(feat, roles, whitelist.get("whitelist", whitelist) if isinstance(whitelist, dict) else whitelist)
        }

        ctx = {
            "role_src": role_of(src, roles),
            "whitelisted": is_whitelisted(src, whitelist)
        }

        cmd = feat.get("cmd") or feat.get("command")
        if cmd and ctx["role_src"] != "control":
            ctx["maybe_control_cmd_from_meter"] = True

        decision = decide_score(thr_flag, rules, ctx)
        if decision:
            write_alert({
                "src": src,
                "dst": feat.get("dst"),
                "attack": decision["attack"],
                "severity": decision["severity"],
                "score": decision.get("score"),
                "details": decision.get("details", ""),
                "role_src": ctx["role_src"],
                "role_dst": "unknown"
            })


def main():
    print(f"[+] IDS running. window={WINDOW_S}s filter='{BPF}' (Ctrl+C to stop)")
    while True:
        pkts = sniff(filter=BPF, store=True, timeout=WINDOW_S)  # capture for window
        process_window(pkts)

if __name__ == "__main__":
    main()
