"""Volumetric DDoS -> unified alerts. Source: the detector's own saved outputs from the
Docker attacker/victim/monitor lab (volumetric-ddos-v2 branch)."""
import json
from datetime import datetime

from common import SOURCES, make_alert, write

SRC = SOURCES / "volumetric-ddos-v2"
FILES = {
    "alerts_output.json": "SYN flood (Branch A)",
    "udp_alerts_output.json": "UDP reflection / amplification (Branch B)",
    "generic_alerts_output.json": "Spoofed-source / generic flood (Branch C)",
}


def main():
    alerts = []
    for fname, branch in FILES.items():
        for rec in json.loads((SRC / fname).read_text()):
            if not rec.get("alert"):
                continue
            ts = rec.get("timestamp")
            captured = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else None
            dst = rec["flow_id"].split("-")[0]
            ev = [{"feature": k, "value": v} for k, v in rec["evidence"].items()]
            alerts.append(make_alert(
                detector="volumetric_ddos_v2", threat="volumetric_ddos",
                confidence=rec["confidence"], captured_ts=captured, evidence=ev,
                dataset=f"Docker attack lab · {branch}", kind="lab",
                dst_ip=dst, proto=rec["flow_id"].split("-")[1],
                entity=f"target {dst}",
                summary=f"{branch}: {rec['threat_class'].replace('_', ' ')}"))
    write("volumetric_ddos", alerts)


if __name__ == "__main__":
    main()
