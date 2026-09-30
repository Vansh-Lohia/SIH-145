"""SimpleX — passive, one-way threat detection dashboard (SIH 2026 · PS 26145).

Replays the real outputs of all six detectors, converted to one unified alert schema,
on a single timeline. Every alert shows where its evidence came from (real capture,
lab-captured traffic or synthetic scenario) and its original capture time.
"""
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="SimpleX · Passive Threat Detection", page_icon="🛡️",
                   layout="wide")

DATA = Path(__file__).parent / "data"
REPLAY_SECONDS = 600
TICK = 1.0
REPO = "https://github.com/Vansh-Lohia/SIH-145"

DETECTOR_OF = {
    "encrypted_malware": "Encrypted Malware", "botnet_c2": "Botnet C2",
    "dga": "DGA / DNS", "dns_tunnelling": "DGA / DNS", "port_scan": "Port Scanning",
    "data_exfiltration": "Data Exfiltration", "volumetric_ddos": "Volumetric DDoS",
}
DETECTORS = ["Encrypted Malware", "Botnet C2", "DGA / DNS", "Port Scanning",
             "Data Exfiltration", "Volumetric DDoS"]
SEV_COLOR = {"critical": "#E5484D", "high": "#F76B15", "medium": "#FFC53D", "low": "#46A758"}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
KIND = {"real": ("Real capture", "#30A46C"), "lab": ("Lab-captured", "#F5A524"),
        "synthetic": ("Synthetic scenario", "#8B8D98")}
STATUS_COLOR = {"MEASURED": "#30A46C", "DEMONSTRATED": "#F5A524", "IN PROGRESS": "#8B8D98"}

st.markdown("""
<style>
.block-container {padding-top: 3.2rem; padding-bottom: 1rem;}
.sx-title {font-size: 2.1rem; font-weight: 800; letter-spacing: -0.02em; margin: 0;}
.sx-sub {color: #9BA7BD; margin: 0.1rem 0 0.6rem 0;}
.pill {display:inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.72rem;
       font-weight: 700; letter-spacing: 0.04em; margin-right: 6px; color: #0B1220;}
.tag {display:inline-block; padding: 3px 10px; border-radius: 6px; font-size: 0.75rem;
      font-weight: 600; margin: 0 6px 6px 0; border: 1px solid #2A3550; color: #C9D3E6;
      background: #121B2E;}
.card {background: #111A2E; border: 1px solid #22304D; border-radius: 12px;
       padding: 14px 16px; height: 100%;}
.card h4 {margin: 0 0 4px 0; font-size: 0.95rem;}
.big {font-size: 1.7rem; font-weight: 800; line-height: 1.1;}
.muted {color: #8C97AD; font-size: 0.8rem;}
.kv {font-size: 0.88rem; margin: 2px 0;}
.kv b {color: #9BA7BD; font-weight: 600; display: inline-block; min-width: 118px;}
.mono {font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.84rem;}
</style>""", unsafe_allow_html=True)


@st.cache_data
def load_alerts():
    rows = [json.loads(l) for l in (DATA / "alerts.jsonl").read_text("utf-8").splitlines() if l]
    for a in rows:
        a["detector_name"] = DETECTOR_OF[a["threat_class"]]
    return sorted(rows, key=lambda a: a["replay_offset_s"])


@st.cache_data
def load_validation():
    return json.loads((DATA / "validation.json").read_text("utf-8"))


def mmss(sec: float) -> str:
    return f"{int(sec) // 60:02d}:{int(sec) % 60:02d}"


def pill(text, color):
    return f"<span class='pill' style='background:{color}'>{text}</span>"


def ground_truth(a):
    gt = [e for e in a["evidence"] if e["feature"] == "ground_truth"]
    return gt[0]["value"] if gt else None


ALERTS = load_alerts()
ss = st.session_state
ss.setdefault("playing", True)
ss.setdefault("t", 0.0)
ss.setdefault("speed", 5)

# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("### ▶ Replay")
    c1, c2 = st.columns(2)
    if c1.button("⏸ Pause" if ss.playing else "▶ Play", use_container_width=True):
        ss.playing = not ss.playing
        st.rerun()
    if c2.button("↺ Restart", use_container_width=True):
        ss.t, ss.playing = 0.0, True
        st.rerun()
    ss.speed = st.select_slider("Speed", options=[1, 5, 10, 30], value=ss.speed,
                                format_func=lambda v: f"{v}×")
    with st.expander("Filters"):
        f_det = st.multiselect("Detectors", DETECTORS, default=DETECTORS)
        f_sev = st.multiselect("Severity", list(SEV_COLOR), default=list(SEV_COLOR))
        f_kind = st.multiselect("Data source", list(KIND), default=list(KIND),
                                format_func=lambda k: KIND[k][0])
    st.divider()
    st.caption("**Replay mode.** Alerts are real outputs of the six detectors, produced from "
               "separate captures (real, lab and synthetic) and merged onto one timeline. "
               "Each alert shows its data source and original capture time.")
    st.caption(f"[Source code ↗]({REPO})")


def visible(t):
    return [a for a in ALERTS if a["replay_offset_s"] <= t and a["detector_name"] in f_det
            and a["severity"] in f_sev and a["source"]["kind"] in f_kind]


# ---------------------------------------------------------------- header
st.markdown("<p class='sx-title'>🛡️ SimpleX · Passive Threat Detection</p>"
            "<p class='sx-sub'>Six detectors on one-way traffic behind a data diode — "
            "observe everything, send nothing back.</p>", unsafe_allow_html=True)
st.markdown("".join(f"<span class='tag'>{t}</span>" for t in
                    ["⇢ ONE-WAY INGEST", "0 PACKETS SENT", "NO PAYLOAD DECRYPTION",
                     "6 DETECTORS · 1 ALERT SCHEMA", "MITRE ATT&CK TAGGED",
                     "VALIDATED ON UNSEEN ATTACKS"]), unsafe_allow_html=True)

tab_live, tab_inv, tab_val, tab_how = st.tabs(
    ["🛰️ Live monitor", "🔎 Investigate alert", "✅ Validation results", "⚙️ How it works"])


# ---------------------------------------------------------------- live monitor
@st.fragment(run_every=TICK)
def live_monitor():
    if ss.playing:
        ss.t = min(REPLAY_SECONDS, ss.t + ss.speed * TICK)
        if ss.t >= REPLAY_SECONDS:
            ss.playing = False
    vis = visible(ss.t)

    st.progress(ss.t / REPLAY_SECONDS,
                text=f"Replay clock {mmss(ss.t)} / {mmss(REPLAY_SECONDS)} · "
                     f"{'playing ' + str(ss.speed) + '×' if ss.playing else 'paused'}")

    k = st.columns(5)
    k[0].metric("Alerts raised", len(vis))
    k[1].metric("Critical + high", sum(a["severity"] in ("critical", "high") for a in vis))
    k[2].metric("Detectors reporting", f"{len({a['detector_name'] for a in vis})} / 6")
    k[3].metric("MITRE techniques", len({a["mitre_technique"] for a in vis}))
    k[4].metric("Packets sent to network", "0", help="Read-only by design: no probes, "
                "no handshakes, no mitigation traffic ever leaves the monitoring enclave.")

    tiles = st.columns(6)
    for col, name in zip(tiles, DETECTORS):
        mine = [a for a in vis if a["detector_name"] == name]
        last = mine[-1] if mine else None
        worst = min((SEV_RANK[a["severity"]] for a in mine), default=None)
        color = [c for s, c in SEV_COLOR.items() if SEV_RANK[s] == worst][0] if mine else "#2A3550"
        col.markdown(
            f"<div class='card' style='border-top:3px solid {color}'>"
            f"<h4>{name}</h4><div class='big'>{len(mine)}</div>"
            f"<div class='muted'>{('last ' + mmss(last['replay_offset_s']) + ' · ' + last['mitre_technique']) if last else 'no alerts yet'}</div>"
            f"</div>", unsafe_allow_html=True)

    st.write("")
    left, right = st.columns([3, 2])
    with left:
        if vis:
            df = pd.DataFrame([{
                "time_s": a["replay_offset_s"], "detector": a["detector_name"],
                "severity": a["severity"], "confidence": a["confidence"],
                "summary": a["summary"], "mitre": a["mitre_technique"]} for a in vis])
            fig = px.scatter(df, x="time_s", y="detector", color="severity",
                             size=df["confidence"].clip(lower=0.15),
                             color_discrete_map=SEV_COLOR, hover_name="summary", size_max=13,
                             hover_data={"mitre": True, "confidence": ":.2f",
                                         "time_s": False, "detector": False},
                             category_orders={"detector": DETECTORS[::-1],
                                              "severity": list(SEV_COLOR)})
            fig.update_layout(height=330, margin=dict(l=10, r=10, t=30, b=10),
                              title=dict(text="Alert timeline", font=dict(size=14)),
                              xaxis=dict(range=[0, REPLAY_SECONDS], title="replay time (s)"),
                              yaxis_title=None, legend_title=None,
                              paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True, key="timeline")
        else:
            st.info("Waiting for the first alert…")
    with right:
        st.markdown("**Live alert feed**")
        feed = [{
            "Time": mmss(a["replay_offset_s"]), "Severity": a["severity"].upper(),
            "Detector": a["detector_name"], "Entity": a["entity"] or "—",
            "Confidence": a["confidence"]} for a in reversed(vis[-40:])]
        st.dataframe(pd.DataFrame(feed), height=330, hide_index=True,
                     use_container_width=True,
                     column_config={
                         "Time": st.column_config.TextColumn(width="small"),
                         "Severity": st.column_config.TextColumn(width="small"),
                         "Entity": st.column_config.TextColumn(width="medium"),
                         "Confidence": st.column_config.ProgressColumn(
                             "Confidence", min_value=0, max_value=1, format="%.2f",
                             width="small")})
    if not ss.playing and ss.t >= REPLAY_SECONDS:
        st.success("Replay complete — open **Investigate alert** for any alert's evidence, "
                   "or press **Restart**.")


with tab_live:
    live_monitor()


# ---------------------------------------------------------------- investigate
with tab_inv:
    pool = visible(REPLAY_SECONDS)
    if not pool:
        st.info("No alerts match the current filters.")
    else:
        pool = sorted(pool, key=lambda a: (SEV_RANK[a["severity"]], -a["confidence"]))
        labels = {a["alert_id"]: f"{a['severity'].upper():8} · {a['detector_name']} · "
                                 f"{a['entity'] or a['summary']}" for a in pool}
        ids = list(labels)
        showcase = next((i for i, a in enumerate(pool) if "2025" in a["source"]["dataset"]
                         and a["threat_class"] == "encrypted_malware"
                         and "unseen" in str(ground_truth(a))), 0)
        pick = st.selectbox("Choose an alert", ids, index=showcase, format_func=labels.get)
        a = next(x for x in pool if x["alert_id"] == pick)
        kind_label, kind_color = KIND[a["source"]["kind"]]
        c1, c2 = st.columns([3, 2])
        with c1:
            f = a["flow_id"]
            flow = " → ".join(x for x in [
                f"{f['src_ip']}:{f['src_port']}" if f["src_ip"] and f["src_port"] else f["src_ip"],
                f"{f['dst_ip']}:{f['dst_port']}" if f["dst_ip"] and f["dst_port"] else f["dst_ip"]]
                if x) or "—"
            st.markdown(
                f"<div class='card'>"
                f"<h3 style='margin:0 0 6px 0'>{a['threat_label']}</h3>"
                f"{pill(a['severity'].upper(), SEV_COLOR[a['severity']])}"
                f"{pill(kind_label.upper(), kind_color)}"
                f"<p style='margin:10px 0 8px 0'>{a['summary']}</p>"
                f"<p class='kv'><b>Entity</b><span class='mono'>{a['entity'] or '—'}</span></p>"
                f"<p class='kv'><b>Flow</b><span class='mono'>{flow}"
                f"{' (' + f['proto'] + ')' if f['proto'] else ''}</span></p>"
                f"<p class='kv'><b>MITRE ATT&amp;CK</b>{a['mitre_technique']} — {a['mitre_name']}</p>"
                f"<p class='kv'><b>Confidence</b>{a['confidence']:.2f}</p>"
                f"<p class='kv'><b>Detector</b><span class='mono'>{a['detector']}</span></p>"
                f"<p class='kv'><b>Data source</b>{a['source']['dataset']}</p>"
                f"<p class='kv'><b>Captured at</b>{a['captured_at'] or 'n/a (scenario time)'}</p>"
                f"</div>", unsafe_allow_html=True)
            gt = ground_truth(a)
            if gt:
                st.caption(f"Ground truth from the labelled capture: **{gt}**")
        with c2:
            st.markdown("**Why this was flagged**")
            ev = [e for e in a["evidence"] if e["feature"] != "ground_truth"]
            contrib = [e for e in ev if "contribution" in e]
            if contrib:
                d = pd.DataFrame(contrib)
                d["label"] = d["feature"] + " = " + d["value"].astype(str)
                fig = px.bar(d.iloc[::-1], x="contribution", y="label", orientation="h",
                             color_discrete_sequence=["#E5484D"])
                fig.update_layout(height=240, margin=dict(l=0, r=10, t=10, b=10),
                                  xaxis_title="push toward malicious (SHAP)", yaxis_title=None,
                                  paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig, use_container_width=True)
                rest = [e for e in ev if "contribution" not in e]
            else:
                rest = ev
            if rest:
                st.dataframe(pd.DataFrame([{"Evidence": e["feature"], "Value": str(e["value"])}
                                           for e in rest]), hide_index=True,
                             use_container_width=True)
        with st.expander("Unified alert (JSON) — the same schema for all six detectors"):
            st.json({k: v for k, v in a.items() if k != "detector_name"})


# ---------------------------------------------------------------- validation
with tab_val:
    val = load_validation()
    st.markdown("#### Every detector is tested on attacks it never saw in training")
    st.caption("Not random train/test splits: held-out malware families, unseen attacker IPs, "
               "independently generated batches and public datasets. "
               f"Last updated {val['updated']}.")
    rows = [val["detectors"][i:i + 3] for i in range(0, len(val["detectors"]), 3)]
    for row in rows:
        cols = st.columns(3)
        for col, d in zip(cols, row):
            col.markdown(
                f"<div class='card'>{pill(d['status'], STATUS_COLOR[d['status']])}"
                f"<h4 style='margin-top:8px'>{d['name']}</h4>"
                f"<div class='big' style='font-size:1.25rem'>{d['headline']}</div>"
                f"<p style='margin:6px 0'>{d['detail']}</p>"
                f"<p class='muted'>{d['method']}</p></div>", unsafe_allow_html=True)
        st.write("")


# ---------------------------------------------------------------- how it works
with tab_how:
    st.graphviz_chart("""
    digraph G {
      rankdir=LR; bgcolor="transparent"; node [shape=box style="rounded,filled"
      fontname="Helvetica" fontsize=11 color="#22304D" fillcolor="#111A2E" fontcolor="#E6EDF7"];
      edge [color="#6B7A99" fontcolor="#9BA7BD" fontsize=9 fontname="Helvetica"];
      prod [label="Production\\nnetwork"];
      diode [label="Hardware\\ndata diode" fillcolor="#1F3A68"];
      ingest [label="Passive ingest\\nZeek + JA4 · PCAP / NetFlow"];
      feat [label="One-way features only\\nsize · timing · fingerprints\\nfan-out · entropy"];
      subgraph cluster_d { label="6 specialist detectors"; fontcolor="#9BA7BD"; color="#22304D";
        d1 [label="Encrypted malware"]; d2 [label="Botnet C2"]; d3 [label="DGA / DNS"];
        d4 [label="Port scanning"]; d5 [label="Exfiltration"]; d6 [label="Volumetric DDoS"]; }
      schema [label="Unified alert schema\\nseverity · confidence\\nMITRE ATT&CK · evidence"
              fillcolor="#1F3A68"];
      out [label="Dashboard · SIEM\\n(Splunk / Elastic / Sentinel)"];
      prod -> diode -> ingest -> feat;
      feat -> {d1 d2 d3 d4 d5 d6};
      {d1 d2 d3 d4 d5 d6} -> schema -> out;
      diode -> prod [style=dashed color="#E5484D" fontcolor="#E5484D" label="no return path ✕"];
    }""", use_container_width=True)
    c1, c2, c3 = st.columns(3)
    c1.markdown("**Read-only by design**  \nNo probes, no handshakes, no mitigation "
                "commands. The monitoring enclave never transmits toward the network.")
    c2.markdown("**Encryption-aware, never decrypting**  \nTLS/QUIC sessions are judged from "
                "handshake fingerprints (JA4) and packet size/timing — not payloads.")
    c3.markdown("**Built for what one-way traffic shows**  \nBackward-direction features "
                "(replies, RTT, handshake completion) don't exist behind a diode, so no "
                "detector depends on them.")
