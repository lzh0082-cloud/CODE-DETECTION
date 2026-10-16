model flash; presentations ['plain', 'verify-show']

| condition | n | acc plain | acc verify-show | verify-show vs plain: lost/gained, p, diff (95% CI) |
|---|---|---|---|---|
| C2 patch-relevant true notes, both versions | 338 | 0.61 | 0.62 | 29/30, p=1.000, +0.00 (-0.04, +0.05) |
| C2 patch-relevant true notes, vulnerable versions | 167 | 0.55 | 0.55 | 17/17, p=1.000, +0.00 (-0.07, +0.07) |
| C4 false reassurance, vulnerable | 141 | 0.54 | 0.66 | 6/23, p=0.002, +0.12 (+0.05, +0.19) |
| C2 patch-relevant true notes, patched versions | 171 | 0.67 | 0.68 | 12/13, p=1.000, +0.01 (-0.05, +0.06) |

Primary test: C4 accuracy vs plain on vulnerable versions, Holm-corrected:
  verify-show n=141 lost/gained 6/23  p=0.0023  Holm-adjusted p=0.0023

Deference gap on vulnerable versions (C4 accuracy - C2 accuracy, same functions):
  plain   n=141  C2 0.60 -> C4 0.54  gap -0.06 (-0.14, +0.01), McNemar p=0.150; lexical dispute cue in C4 answers 56/141
  verify-show n=141  C2 0.61 -> C4 0.66  gap +0.05 (-0.02, +0.13), McNemar p=0.296; lexical dispute cue in C4 answers 114/141
