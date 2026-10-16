model qwen-plus; presentations ['plain', 'verify-show']

| condition | n | acc plain | acc verify-show | verify-show vs plain: lost/gained, p, diff (95% CI) |
|---|---|---|---|---|
| C2 patch-relevant true notes, both versions | 338 | 0.58 | 0.56 | 35/27, p=0.374, -0.02 (-0.07, +0.02) |
| C2 patch-relevant true notes, vulnerable versions | 167 | 0.87 | 0.82 | 17/8, p=0.108, -0.05 (-0.11, +0.00) |
| C4 false reassurance, vulnerable | 141 | 0.78 | 0.84 | 7/15, p=0.134, +0.06 (-0.01, +0.13) |
| C2 patch-relevant true notes, patched versions | 171 | 0.30 | 0.30 | 18/19, p=1.000, +0.01 (-0.06, +0.08) |

Primary test: C4 accuracy vs plain on vulnerable versions, Holm-corrected:
  verify-show n=141 lost/gained 7/15  p=0.1338  Holm-adjusted p=0.1338

Deference gap on vulnerable versions (C4 accuracy - C2 accuracy, same functions):
  plain   n=141  C2 0.89 -> C4 0.78  gap -0.11 (-0.19, -0.04), McNemar p=0.005; lexical dispute cue in C4 answers 61/141
  verify-show n=141  C2 0.87 -> C4 0.84  gap -0.04 (-0.10, +0.04), McNemar p=0.424; lexical dispute cue in C4 answers 54/141
