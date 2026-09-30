"""Port scanning -> unified alerts. Runs the REAL ReconDetector (port_scanning branch) over its
own built-in strict one-way synthetic scenarios (vertical, horizontal, mixed, slow, UDP,
camouflaged ...). One alert per scanning source, at the moment the detector first fires."""
import sys

from common import SOURCES, make_alert, write

SRC = SOURCES / "port_scanning"
sys.path.insert(0, str(SRC / "src"))

from recon_detector import ReconDetector  # noqa: E402
from recon_detector import synthetic  # noqa: E402

EVIDENCE_KEYS = ["unique_destination_ports", "unique_destination_hosts", "observed_flows",
                 "destination_port_entropy", "scan_like_flow_ratio", "persistence"]


def _detector():
    try:
        return ReconDetector.from_model_dir(SRC / "models_docker")
    except Exception as exc:  # model/sklearn mismatch -> the detector's own heuristic scorer
        print(f"  (trained model unavailable: {exc}; using heuristic flow scorer)")
        return ReconDetector()


def main():
    alerts = []
    for name, fn in synthetic.SCENARIOS.items():
        det = _detector()
        fired = set()
        for rec in fn():
            res = det.process(rec)
            if not res.detected or res.source in fired:
                continue
            fired.add(res.source)
            ev = [{"feature": k, "value": res.evidence.get(k)} for k in EVIDENCE_KEYS
                  if k in res.evidence]
            ev.append({"feature": "scan_type", "value": res.scan_type})
            alerts.append(make_alert(
                detector="recon_detector", threat="port_scan", confidence=res.score,
                captured_ts=None, evidence=ev,
                dataset=f"Strict one-way scenario: {name}", kind="synthetic",
                src_ip=res.source, entity=f"source {res.source}",
                summary=f"{res.scan_type} scan from {res.source} "
                        f"({res.evidence.get('unique_destination_ports')} ports, "
                        f"{res.evidence.get('unique_destination_hosts')} hosts)"))
    write("port_scan", alerts)


if __name__ == "__main__":
    main()
