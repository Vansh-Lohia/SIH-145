# Prototype evaluation notes

Follows the protocol in `CLAUDE.md` §7 (Arp et al., *Dos and Don'ts of ML in Computer
Security*, USENIX '22). All numbers below are on **synthetic prototype data** — they
demonstrate that the pipeline and the evaluation discipline work, not real-world accuracy.

## Report format

```
split_type | TPR@0.1%FPR | precision | recall | F1 | alerts/hr | p99 latency
```

Never accuracy or balanced accuracy alone — real traffic is ~99.9% benign.

## The headline finding: random split vs leave-one-family-out

Representative run (`python scripts/run_prototype.py`, seed 42):

| split | TPR@0.1%FPR |
|---|---|
| random, **split by capture file** (optimistic) | ~0.86 |
| **leave-one-family-out** (headline) | ~0.47 mean |

Per held-out family, the gap is concentrated exactly where theory predicts:

| held-out family | TPR@0.1%FPR | why |
|---|---|---|
| `zeus`, `trickbot` | high | distinct JA4 **and** a beacon timing signature — both partly generalise |
| `cobaltstrike`, `quicc2` | ~0.0 | mimic a browser's JA4 and (cobaltstrike) don't beacon → nearly invisible when unseen |

**The gap between the two numbers is the result worth presenting.** A detector reported only
on the random split would look like ~0.86; the honest number a defender should plan around
is the ~0.47, and the reason is generalisation to unseen families — the same failure that
took our DGA module from 95.6% to ~0% recall.

## Ablation (which family carries the signal)

| features | TPR@0.1%FPR |
|---|---|
| shape/timing only | ~0.77 |
| handshake (JA4) only | ~0.59 |
| combined | ~0.86 |

Neither family alone is sufficient, and handshake-only is the weaker pillar — concrete
support for the ECH argument (`CLAUDE.md` §3): as Encrypted Client Hello erodes the JA4
signal, the shape/timing family must carry the detector.

## Fingerprints are features, not signatures — and a leakage bug we caught

The baseline uses the JA4 hash via **smoothed target encoding**, never as a lookup key
(`CLAUDE.md` §6.1). During bring-up the first synthetic generator produced a **unique JA4
per session** (it randomised the cipher subset each time). Target encoding then memorised
each session's own label, giving a perfect random-split score that **collapsed on the test
set** — every test JA4 was unseen and fell back to the prior. This is precisely the "JA4
blocklist wearing an ML hat" failure the contract warns about, reproduced by accident.

The fix models reality: fingerprints are **shared** across many sessions. The generator now
emits a small set (~10) of fixed handshake templates, with browser-mimicking malware sharing
the browser templates. Target encoding is then meaningful and non-leaky. See
`tests/test_pipeline.py::test_shared_ja4_cardinality_is_realistic`, which guards against a
regression.

## Feature-family availability (`CLAUDE.md` §3)

Reported every run. On synthetic data: shape 100%, handshake 100%, certificate ~17% (TLS 1.2
only). Certificate features are gated on TLS version and carry a `cert_features_available`
flag so the model ignores them when absent rather than reading silent zeros.

## Latency

Per-session scoring p99 is ~2 ms on CPU; the end-to-end target is < 30 s from session start
(`CLAUDE.md` §4), dominated in production by waiting for the first N packets, not by scoring.

## What this is NOT

Synthetic data cannot prove real-world accuracy, and the numbers here are a property of the
generator. The real evaluation runs on Stratosphere/CTU malware captures with
self-generated benign traffic on the same network/period (`CLAUDE.md` §8), holding one
dataset completely unseen until the final week (§7 rule 7). The value of the prototype is
that the *protocol* — split by capture, leave-one-family-out, TPR@0.1%FPR, alerts/hour,
feature sanity check — is already in place and enforced by tests.

## First real result (CTU captures)

`python scripts/build_dataset.py --scan --eval` on real captures — Dridex (CTU-251-1),
Trickbot (CTU-327-2), Emotet (CTU-264-1), plus benign traffic from CTU-Normal-26:

```
LOFO:dridex     TPR@0.1%FPR = 0.0000
LOFO:emotet     TPR@0.1%FPR = 0.3050
LOFO:trickbot   TPR@0.1%FPR = 0.0000
mean (headline)             = 0.1017
```

**This is a genuinely bad number, and that is the correct, expected result at this stage.**
Two things explain it, both already flagged by the tooling itself:

1. **Environment confound (CLAUDE.md §7's central warning).** All malicious sessions come
   from `ctu-sandbox` captures; all benign sessions come from `ctu-normal`/`lab`. The model
   can partly learn "which capture environment is this?" rather than "malicious vs benign" —
   `build_dataset.py --eval` now detects and prints this warning automatically whenever the
   two label classes don't share an environment.
2. **Real families barely resemble each other.** Dridex is TLS 1.2, no SNI, one C2 IP pair.
   Trickbot is TLS 1.0, its own JA4. Emotet's ClientHellos were too minimal for FoxIO's JA4
   package to compute a hash at all (`ja4` field literally `"(empty)"` — see below). A
   detector trained on Dridex+Trickbot has essentially no shared signal to transfer to
   Emotet, and vice versa. This is leave-one-family-out doing exactly its job: refusing to
   let a detector's score on familiar malware stand in for its score on the next one.

The random-split comparison point is **not reportable yet**: with only 5 total pcaps (one
per malware family, two benign), a 30% file-level split is coarse enough to produce a
degenerate test set (e.g. 0 malicious / 2 benign sessions) — `build_dataset.py` detects this
and skips the row rather than printing a misleading 0.0000. More captures per class are
needed before random-split-vs-LOFO is a fair comparison on real data.

### Bug found in real ingestion: FoxIO's `"(empty)"` JA4 sentinel

Zeek's own unset-scalar marker is `-`, already handled. FoxIO's JA4 package additionally
emits the literal string `"(empty)"` in the `ja4` field when it cannot compute a hash (seen
on 100% of the Emotet capture's 14,060 sessions — an unusually minimal ClientHello). Before
the fix, `ingest/zeek_reader.py` treated `"(empty)"` as a real, universally-shared
fingerprint, which would have silently corrupted the JA4 target encoding across the entire
Emotet family. Fixed by treating `"(empty)"` (alongside `-`) as no-value in
`_clean_str()`, so those sessions correctly report `handshake` unavailable instead.

### Feature-family availability on real data

`shape=100%, handshake=41%, certificate=29%` — shape is always available as designed;
handshake drops because of the Emotet `(empty)` JA4 issue above; certificate is TLS-1.2-only
by design and most of the corpus (by session count) is Emotet/Dridex over older TLS or with
gaps in the x509 join. This is exactly the "losing a family should degrade, not break, the
detector" property the architecture was built for (`CLAUDE.md` §3) — and it is now visible
on real data, not just asserted.

### Next steps toward a trustworthy real number

1. Add more malware families (more pcaps) so leave-one-family-out isn't estimated from n=3.
2. Generate benign traffic **inside the same environment** as a malware replay — closing the
   environment confound is higher priority than adding more malware families.
3. Investigate why FoxIO couldn't compute JA4 for the Emotet capture — is it truncation in
   the CTU pcap, or a genuinely minimal ClientHello worth featurizing on its own?
