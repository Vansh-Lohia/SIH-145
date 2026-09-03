"""Models (CLAUDE.md §4).

- baseline: LightGBM on tabular features. Build FIRST; often competitive, always faster.
- sequence: 1D-CNN over first N packets (not LSTM).
- fusion: concat CNN embedding into the GBM, or average scores — only after both work.

Do not build the sequence model before the baseline reports an honest
leave-one-family-out number (CLAUDE.md §9, §10).
"""
