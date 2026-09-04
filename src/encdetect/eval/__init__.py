"""Evaluation protocol — the part that decides credibility (CLAUDE.md §7).

Follows Arp et al., "Dos and Don'ts of ML in Computer Security", USENIX Security 2022.

Mandatory rules:
  1. Never split flows from the same pcap across train/test — split by capture file.
  2. Hold out entire malware families (train A-H, test I-J). This is the HEADLINE number.
  3. Split temporally where dates allow.
  4. Report TPR at fixed low FPR (0.1%). Never balanced accuracy or accuracy alone.
  5. Report alerts/hour at the operating point.
  6. Sanity-check top features for environment artifacts (TTL, timestamps, single-capture
     cipher suites).
  7. Hold one dataset completely unseen until the final week.
"""
