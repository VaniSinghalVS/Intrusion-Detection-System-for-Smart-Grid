from collections import defaultdict
import re

def _extract_cmd_from_bytes(b: bytes):
    try:
        s = b.decode("utf-8", errors="ignore")
    except:
        return ""
    m = re.search(r'\b(CMD:?[A-Z_]+|RESET|OPEN_VALVE|START|STOP|READ)\b', s, flags=re.IGNORECASE)
    return m.group(0) if m else ""

def features_from_packets(packets):
    by_src = defaultdict(lambda: {"syn_count":0, "icmp_req":0, "dst_ports":set(), "details_list": [], "cmd": ""})
    for p in pacSkets:
        src = dst = None
        try:
            ip = p.getlayer("IP")
            if ip:
                src = ip.src
                dst = ip.dst
            else:
                ip6 = p.getlayer("IPv6")
                if ip6:
                    src = ip6.src
                    dst = ip6.dst
        except Exception:
            pass

        if not src or not dst:
            try:
                eth = p.getlayer("Ether")
                if eth:
                    src = getattr(eth, "src", src)
                    dst = getattr(eth, "dst", dst)
            except Exception:
                pass

        if not src:
            continue   

    out = []
    for v in by_src.values():
        v["dst_ports"] = list(v["dst_ports"])
        v["details"] = " | ".join(v["details_list"][-3:]) if v.get("details_list") else ""
        v["cmd"] = v.get("cmd", "")
        v.pop("details_list", None)
        out.append(v)
    return out
