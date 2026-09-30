"""Data exfiltration -> unified alerts. Source: the detector's own saved alert output
(analysis/alerts.csv) from the network-namespace mirror lab (data-exfiltration branch).
Only rows the detector raised on attack traffic are shown; benign false positives are kept
too, labelled as such, because hiding them would misrepresent the detector."""
import csv

from common import SOURCES, make_alert, write

SRC = SOURCES / "data-exfiltration" / "analysis" / "alerts.csv"


def main():
    alerts = []
    with SRC.open(newline="") as fh:
        for row in csv.DictReader(fh):
            conf = float(row["alert_confidence"])
            if conf <= 0:
                continue
            reasons = [r.strip() for r in row["alert_reasons"].split(";") if r.strip()]
            truth = row["label"]
            alerts.append(make_alert(
                detector="data_exfiltration", threat="data_exfiltration",
                confidence=conf, captured_ts=float(row["timestamp"]),
                evidence=[{"feature": "reason", "value": r} for r in reasons]
                + [{"feature": "ground_truth", "value": truth}],
                dataset="Mirrored namespace lab (Zeek conn.log)", kind="lab",
                src_ip=row["id.orig_h"], dst_ip=row["id.resp_h"],
                dst_port=int(row["id.resp_p"]), proto="tcp",
                entity=f"{row['id.orig_h']} → {row['id.resp_h']}:{row['id.resp_p']}",
                summary=reasons[0] if reasons else "exfiltration pattern"))
    write("data_exfiltration", alerts)


if __name__ == "__main__":
    main()
