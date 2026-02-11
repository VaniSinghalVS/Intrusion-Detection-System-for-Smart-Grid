# app.py — diagnostic + robust loader for Smart Grid IDS
import json
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Smart Grid IDS", layout="wide")
st.title("Smart Grid IDS — Live Alerts")

# ---------------- UI controls ----------------
default_log = r"D:\smartgrid_ids\intrusion_log.txt"
log_path = st.sidebar.text_input("Log file (absolute path)", default_log)
window_mins = st.sidebar.slider("Show last N minutes", 60, 1440, 1440)
if st.sidebar.button("Refresh now"):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.write("Diagnostics enabled: shows parsing stats and samples.")

# ---------------- robust loader + diagnostics ----------------
def try_parse_iso(ts_str):
    """Try several iso-style parses; return timezone-aware datetime or None."""
    if ts_str is None:
        return None
    if not isinstance(ts_str, str):
        ts_str = str(ts_str)
    s = ts_str.strip()
    if not s:
        return None
    # try direct pandas parse first
    try:
        dt = pd.to_datetime(s, utc=True)
        if pd.isna(dt):
            raise ValueError("pandas returned NaT")
        return dt.to_pydatetime().astimezone(timezone.utc)
    except Exception:
        pass
    # try python fromisoformat with Z -> +00:00
    try:
        clean = s.replace("Z", "+00:00")
        return datetime.fromisoformat(clean).astimezone(timezone.utc)
    except Exception:
        pass
    # last resort: try slicing common formats (YYYY-MM-DDTHH:MM:SS)
    try:
        base = s.split(".")[0].replace("Z", "")
        return datetime.fromisoformat(base).replace(tzinfo=timezone.utc)
    except Exception:
        return None

def load_and_diagnose(path):
    p = Path(path)
    diag = {}
    if not p.exists():
        diag["error"] = f"File not found: {p.resolve()}"
        return diag, pd.DataFrame()

    raw = p.read_text(encoding="utf-8", errors="ignore")
    lines = raw.splitlines()
    diag["raw_chars"] = len(raw)
    diag["raw_lines"] = len(lines)

    total = 0
    json_ok = 0
    ts_ok = 0
    ts_fail_examples = []
    rows = []

    for ln in lines:
        total += 1
        s = ln.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
            json_ok += 1
        except Exception:
            if len(ts_fail_examples) < 5:
                ts_fail_examples.append(("bad-json", s[:300]))
            continue

        # normalize keys to lowercase
        obj = {k.lower(): v for k, v in obj.items()}
        raw_ts = obj.get("ts") or obj.get("timestamp") or obj.get("time")
        parsed = try_parse_iso(raw_ts)
        if parsed is not None:
            ts_ok += 1
            # ensure ts stored as pandas-friendly string (ISO)
            obj["ts"] = parsed
            rows.append(obj)
        else:
            if len(ts_fail_examples) < 10:
                ts_fail_examples.append(("bad-ts", (raw_ts, s[:300])))

    diag["total_lines"] = total
    diag["json_ok"] = json_ok
    diag["ts_ok"] = ts_ok
    diag["ts_fail_examples"] = ts_fail_examples[:10]

    # === EXTRA DEBUG INFO ADDED ===
    diag["rows_appended_count"] = len(rows)
    # collect the last 12 'ts' strings added to rows (or fewer)
    diag["rows_last_ts_samples"] = [r.get("ts") for r in rows[-12:]]
    # also show first 12 ts samples for completeness
    diag["rows_first_ts_samples"] = [r.get("ts") for r in rows[:12]]
    # print one sample raw JSON line near the end for inspection
    diag["rows_last_raw_sample"] = lines[-1] if lines else None
    # ==============================
    # === IMMEDIATE DEBUG: show rows list details before building DataFrame ===
    # (these lines print inside Streamlit so we can compare with raw counts)
    #st.write("DEBUG rows_appended_count (len(rows)):", len(rows))
    #st.write("DEBUG rows_first_5_ts:", [r.get("ts") for r in rows[:5]])
    #st.write("DEBUG rows_last_5_ts:", [r.get("ts") for r in rows[-5:]])
    # ========================================================================

    # build dataframe from rows that had parsed ts
    if rows:
        df = pd.DataFrame(rows)
        # ensure columns exist
        for col in ["ts","src","dst","attack","severity","details","role_src","role_dst"]:
            if col not in df:
                df[col] = None
        df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
        df = df.dropna(subset=["ts"]).sort_values("ts")
    else:
        df = pd.DataFrame(columns=["ts","src","dst","attack","severity","details","role_src","role_dst"])

    return diag, df


# ---------------- load + display diagnostics ----------------
diag, df = load_and_diagnose(log_path)

st.markdown("## Parsing diagnostics")
if "error" in diag:
    st.error(diag["error"])
    st.stop()

#st.write("RAW chars:", diag.get("raw_chars"))
#st.write("RAW total lines:", diag.get("raw_lines"))
#st.write("JSON parse OK:", diag.get("json_ok"))
#st.write("Lines with parseable ts:", diag.get("ts_ok"))
#st.write("Sample ts-parse failures (up to 10):", diag.get("ts_fail_examples"))

st.write("---")
st.write("**DataFrame rows (after ts parsing):**", len(df))
if len(df):
    st.write("Timestamps (UTC):", df["ts"].min(), "→", df["ts"].max())

# ---------- dashboard view ----------
# ---------- dashboard view (debugging filter) ----------
st.markdown("---")
st.header("Dashboard view (debug mode)")

# show dataframe summary
#st.write("DataFrame total rows (after ts parsing):", len(df))
#if len(df):
    #st.write("DataFrame ts min (UTC):", df["ts"].min())
    #st.write("DataFrame ts max (UTC):", df["ts"].max())

# compute cutoff and debug why filter returns 0
now_utc = pd.Timestamp.now(tz="UTC")
#st.write("Current time (UTC):", now_utc)

cutoff = now_utc - pd.Timedelta(minutes=window_mins)
#st.write("Slider window_mins:", window_mins)
#st.write("Computed cutoff (UTC):", cutoff)

if len(df):
    max_ge_cutoff = df["ts"].max() >= cutoff
    #st.write("Is df['ts'].max() >= cutoff ?", bool(max_ge_cutoff))
    #st.write("Rows with ts >= cutoff (should appear):", int((df["ts"] >= cutoff).sum()))
    # show latest 5 timestamps from df
    #st.write("Latest 5 timestamps in df (UTC):", list(df["ts"].tail(5)))

# apply the selected time window filter
cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(minutes=window_mins)
dff = df[df["ts"] >= cutoff]

# if nothing in the very recent window, you may fallback to show last 24 hours
if dff.empty and not df.empty:
    fallback_cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=24)
    dff = df[df["ts"] >= fallback_cutoff]

if dff.empty:
    st.info("No alerts with parseable timestamps found. Generate some test events or check the log file.")
else:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerts (window)", len(dff))
    c2.metric("Unique sources", int(dff["src"].nunique()))
    c3.metric("Attack types", int(dff["attack"].nunique()))
    c4.metric("High severity", int((dff["severity"].astype(str).str.lower() == "high").sum()))

    st.subheader("Alerts per minute")
    st.line_chart(dff.set_index("ts").resample("1min").size())

    colA, colB = st.columns(2)
    with colA:
        st.subheader("Top sources")
        st.bar_chart(dff["src"].value_counts().head(10))
    with colB:
        st.subheader("Attack distribution")
        st.bar_chart(dff["attack"].value_counts())

    st.subheader("Recent alerts")
    show = dff.sort_values("ts", ascending=False)[["ts","severity","attack","src","dst","details","role_src"]]
    st.dataframe(show, use_container_width=True)
