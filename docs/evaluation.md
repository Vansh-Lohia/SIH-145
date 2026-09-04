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

### Update: adding more benign volume made the number WORSE, not better

Added a second benign source, CTU-Normal-28 (2,697 more real sessions; total real corpus now
26,478 sessions, 3 malware families + 2 benign captures). Result:

```
LOFO:dridex     TPR@0.1%FPR = 1.0000
LOFO:emotet     TPR@0.1%FPR = 1.0000
LOFO:trickbot   TPR@0.1%FPR = 1.0000
mean (headline)             = 1.0000
```

**A perfect 1.0000 across three very different, wholly unrelated malware families is a red
flag, not a result to report.** Feature sanity check (CLAUDE.md §7 rule 6) on the held-out-
Dridex model:

```
size_mean       importance=550
ja4_ext_count   importance=266
size_std        importance=161
iat_mean        importance=142
```

These are architecturally the *right* features to matter (SPLT is designed to carry exactly
this signal) — but combined with the known environment confound, perfect separation across
unrelated families is more consistent with the model learning **"raw executable's minimal
TLS client vs. a real browser"** than "malicious vs. benign" specifically. All three malware
captures are unattended Windows binaries making bare TLS connections (few extensions, small
uniform packets); both benign captures are real user browser traffic (many extensions,
larger varied packets). That distinction is real, but it isn't the distinction the detector
needs to make in production, where plenty of legitimate non-browser software (update
checkers, background services, IoT agents) also makes minimal TLS connections.

**Neither the 0.10 first result nor this 1.00 second result should be reported as the
detector's real-world performance.** Both are downstream of the same unresolved root cause:
malicious and benign sessions were captured in different environments by different kinds of
software. `docs/live_capture_investigation.md` records the attempt to fix this at the source
(live same-environment capture) and why it's currently blocked (no root in the available
WSL environment). Two CTU sources that could partially disentangle "sandbox vs. browser" from
"malicious vs. benign" — a benign non-browser TLS client (e.g., a Windows Update capture) and
a malicious capture that isn't pre-filtered to infected-host-only traffic — were searched for
and not found among the captures checked so far.

### Update: live capture unblocked, and the "browser artifact" theory did NOT hold up

`docs/live_capture_investigation.md` recorded that live packet capture was blocked (no
`CAP_NET_RAW` without an interactive sudo password). The user later ran, once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
```

That unblocked live capture permanently. `scripts/capture_live_benign.sh` was built and run:
it scripts real HTTPS visits (curl, not a browser — 31 popular real domains) while `tcpdump`
records the actual wire traffic, for 2 minutes on this live WSL host. Result: 237 genuine
TLS 1.3 sessions, JA4 `t13d3013h2_…` (a real curl/OpenSSL fingerprint), captured **today**,
not downloaded. Labelled `environment: live-wsl-2026` and added to the dataset (now 26,715
sessions).

**Diagnostic: does malicious-vs-benign separation survive when benign is non-browser?**
The earlier 1.0000 result was suspected to be "sandboxed executable's minimal TLS client vs.
a real browser" rather than genuine malice detection. curl is *also* a minimal, non-browser
TLS client — so if that theory were right, malicious-vs-curl-benign should be much harder
than malicious-vs-real-browser-benign was. It measured the opposite:

```
LOFO:dridex     mal score mean=1.0000  benign score mean=0.0000  (TPR@0.1%FPR = 1.0000)
LOFO:emotet     mal score mean=1.0000  benign score mean=0.0000  (TPR@0.1%FPR = 1.0000)
LOFO:trickbot   mal score mean=1.0000  benign score mean=0.0000  (TPR@0.1%FPR = 1.0000)
```

(First attempt at this diagnostic was itself buggy twice, worth recording so it isn't
repeated: (a) running it through `protocol.leave_one_family_out()` with only one benign pcap
put the *entire* file into the test split — rule 1's file-level split logic degenerates when
there's only one file per class, silently training with **zero** benign examples; (b) a
naive manual fix then put the *same* benign sessions in both train and test, leaking. The
number above uses a proper 50/50 held-out split of the live-benign *sessions* — a deliberate,
documented deviation from strict pcap-level splitting, justified only because this is a
single homogeneous capture of repeated scripted requests, not multiple distinct attacker
sessions where rule 1's concern about capture-specific artifacts leaking across the split
would actually apply.)

**This weakens, but doesn't eliminate, the environment-confound concern.** Non-browser benign
traffic separates from malware just as cleanly as browser benign traffic did, which argues
against "minimal client" being the whole story. What remains unruled-out: (1) **temporal
mismatch** — this benign capture is from 2026; the malware captures are 2016–2018, so TLS
version distribution alone (this capture is 100% TLS 1.3; the malware is entirely TLS 1.0/1.2)
could still be doing a lot of the separating work, independent of malice; (2) **duration/
beaconing** — C2 sessions in these captures run long with periodic beacons, while curl's
one-shot GETs are short, and "long + periodic" is a real malicious indicator but also
plausibly present in some legitimate long-lived connections (streaming, sync clients) not
represented in this quick capture. True resolution still needs a malware pcap replayed
through `tcpreplay` onto the *same* live interface as the benign capture, which is not yet
installed (`tcpreplay` needs a package install, a separate ask from the `tcpdump` setcap
already granted) — noted as the concrete remaining step, not a blocker on further work.

### Full metrics (accuracy, precision, recall, F1, AUC) — and a second split bug found while computing them

Asked to report accuracy/precision/recall/F1 directly, computing them surfaced a second real
bug: `split_by_capture_file` picked pcaps for the test side **by pcap count, not by session
weight**. With one 2-session fixture pcap alongside three much larger real captures, "1 of 4
pcaps" for test could trivially land on the tiny one — every leave-one-family-out fold's
benign test set turned out to be the *same 2 sessions*, regardless of the ~4,350 other real
benign sessions sitting in train. Metrics computed from that were not meaningful (accuracy at
a naive 0.5 threshold came out as 0.0003 for one fold purely because LightGBM's raw
probability scale is tiny and uncalibrated — nothing to do with model quality). Fixed by
accumulating pcaps into the test side until they cover `test_fraction` of total **sessions**,
not pcaps; regression test added (26 tests total pass).

With that fixed, all four benign pcaps are properly represented and each fold's benign test
set is a real ~1,416-session sample:

**Real data (CTU), leave-one-family-out, at the TPR@0.1%FPR operating threshold:**

| held-out | n_malicious | n_benign | accuracy | precision | recall | F1 | AUC |
|---|---|---|---|---|---|---|---|
| dridex | 5,735 | 1,416 | 0.9997 | 0.9997 | 1.0000 | 0.9998 | 1.0000 |
| emotet | 14,060 | 1,416 | 0.9999 | 0.9999 | 1.0000 | 0.9999 | 1.0000 |
| trickbot | 2,570 | 1,416 | 0.9997 | 0.9996 | 1.0000 | 0.9998 | 1.0000 |

These are now statistically sound (large samples both sides) but **still the confounded
result** described above — near-perfect across three unrelated families is the environment
artifact, not validated real-world performance.

**Synthetic prototype data, for contrast** (deliberately built so malware overlaps benign in
shape/timing and some families mimic a browser's JA4 — see the synthetic-generator section
above):

| split | n_malicious | n_benign | accuracy | precision | recall | F1 | AUC |
|---|---|---|---|---|---|---|---|
| random-by-capture | 220 | 480 | 0.9543 | 0.9947 | 0.8591 | 0.9220 | 0.9567 |
| LOFO: cobaltstrike | 200 | 450 | 0.6908 | 0.0000 | 0.0000 | 0.0000 | 0.5788 |
| LOFO: quicc2 | 200 | 450 | 0.6908 | 0.0000 | 0.0000 | 0.0000 | 0.5148 |
| LOFO: trickbot | 200 | 450 | 0.9569 | 0.9943 | 0.8650 | 0.9251 | 0.9990 |
| LOFO: zeus | 200 | 450 | 0.9985 | 0.9950 | 1.0000 | 0.9975 | 1.0000 |

This is what an *honest*, appropriately-hard result looks like: two browser-mimicking
families (cobaltstrike, quicc2) genuinely fail when held out (AUC ≈ 0.5, i.e. no better than
chance), because the generator was deliberately built so JA4 alone can't catch them. The real
data doesn't yet show this kind of family-dependent variation — another sign its near-perfect
numbers reflect the environment confound rather than genuine per-family difficulty.

### Testing generalization to a modern (TLS 1.3) malware family

Tested directly: does the current baseline detect a **real, modern malware sample** it never
trained on? Downloaded a confirmed-malicious capture from malware-traffic-analysis.net —
**Lumma Stealer, 2025-08-15, with SectopRAT/Arechclient2** — run through the identical
Zeek+JA4+SPLT pipeline. 10 TLS sessions, all genuine C2 traffic (9 beaconing to
`vishneviyjazz.ru`, 1 to a Cloudflare-fronted `desk-app-now.com`, one shared JA4
`t13d201200_2b729b4bf6f3_e24568c0d440`), **all TLS 1.3** — a TLS version none of the training
malware (2016-2018 CTU) ever uses.

### Correction: an initial naive-threshold check gave a wrong answer

The first pass called `predict_proba(x) > 0.5` "detected" and concluded the model missed
100% of the sample, scoring it "confidently benign." **That conclusion was wrong, and the
method that produced it was wrong.** LightGBM's raw `predict_proba` output in this pipeline
sits in a tiny, uncalibrated range — sometimes ~1e-7, sometimes ~0.16, depending on the
training set — for BOTH classes. A fixed 0.5 cutoff on scores that never approach 0.5 tells
you nothing about discrimination; it only reflects the output's absolute scale, which this
model was never calibrated to match against 0.5. This is exactly the kind of naive-accuracy
mistake `CLAUDE.md` §7 warns about, just showing up in an ad-hoc check instead of a metric.

**Recomputed properly, with rank-based separation (AUC), the actual finding is different:**

```
model trained on synthetic (or real CTU) old-TLS-only malicious data
  vs. real 2025 Lumma Stealer (TLS 1.3, unseen family, unseen TLS version):  AUC = 1.0000
```

Confirmed consistent across three independent random 200-session benign subsamples (not a
fluke of one comparison), and true for a model trained on the real CTU corpus as well as one
trained on synthetic data. Inspecting *why*: the dominant SHAP contributions for a Lumma
session are shape/timing-adjacent (`size_max`, `total_bytes`) alongside some JA4 components,
and the raw feature comparison against a live 2026 benign session shows Lumma's packet size
(mean 780 vs 358), inter-arrival time (std 84.6 vs 15.5), and session duration (777ms vs
285ms) are all substantially higher — consistent with genuine C2 beaconing behavior, not
merely "which TLS version." This lines up with `CLAUDE.md`'s original design premise that
shape/timing is the most durable feature family, precisely because it doesn't depend on
handshake specifics that erode with ECH or evolve with TLS versions.

**What this does and doesn't show:**
- It does show the shape/timing features carry real, transferable signal — the model isn't
  *purely* an "old TLS version" detector, which was the strong claim in the retracted
  conclusion above.
- It does NOT show the detector is production-ready. This is one campaign, n=10 sessions,
  one C2 infrastructure. The synthetic generator's `cobaltstrike`/`quicc2` families exist
  specifically because a C2 tuned to mimic normal traffic shape (jittered timing, browser-like
  sizes) can and does evade shape-based detection — real adversaries adapt. A single clean
  AUC on a small sample is encouraging, not proof of general modern-malware coverage.
- The environment confound (§7's concern) is still not *closed* — benign and malicious still
  come from different capture setups overall — but this specific test is real evidence
  *against* the strongest form of that concern ("the model has learned nothing but era"),
  not evidence for it. The retracted conclusion above overstated the case in the wrong
  direction; this corrected one is the one to rely on.

`lumma-2025-08-15` is committed as a labelled capture (`data/labels/lumma-2025-08-15.jsonl`,
family `lumma_stealer`, environment `mta-net-2025`) so this test is reproducible.
`tests/test_modern_malware_generalization.py` asserts AUC, not a raw-score cutoff, to avoid
repeating the mistake above.

### Next steps toward a trustworthy real number

1. Add more modern (TLS 1.3) malware families/campaigns to test whether the AUC=1.0 result
   holds up across more than one C2 infrastructure — n=10 from a single campaign is not
   enough to generalize the "shape/timing transfers" conclusion with confidence.
2. Install `tcpreplay` and replay a malware pcap onto the same live interface as a benign
   capture, so TLS-version/era and network-stack artifacts are controlled for directly.
3. Add more malware families (both eras) so leave-one-family-out isn't estimated from n=3-4.
4. Test against a C2 sample deliberately tuned to mimic browser-like shape/timing (the
   synthetic `cobaltstrike`/`quicc2` families model this) — the real adversarial case shape
   features alone can't be expected to catch.
5. Investigate why FoxIO couldn't compute JA4 for the Emotet capture — is it truncation in
   the CTU pcap, or a genuinely minimal ClientHello worth featurizing on its own?
