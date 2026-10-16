model flash; presentations ['plain', 'verify', 'verify-show', 'commit']

| condition | n | acc plain | acc verify | acc verify-show | acc commit | verify vs plain: lost/gained, p, diff (95% CI) | verify-show vs plain: lost/gained, p, diff (95% CI) | commit vs plain: lost/gained, p, diff (95% CI) |
|---|---|---|---|---|---|---|---|---|
| C1 all true notes, both versions | 474 | 0.55 | 0.56 | 0.55 | 0.60 | 32/33, p=1.000, +0.00 (-0.03, +0.04) | 37/37, p=1.000, +0.00 (-0.04, +0.04) | 36/59, p=0.023, +0.05 (+0.01, +0.09) |
| C2 patch-relevant true notes, both versions | 235 | 0.59 | 0.58 | 0.60 | 0.64 | 21/18, p=0.749, -0.01 (-0.06, +0.04) | 19/21, p=0.875, +0.01 (-0.04, +0.06) | 20/32, p=0.126, +0.05 (-0.01, +0.11) |
| C2 patch-relevant true notes, vulnerable versions | 120 | 0.58 | 0.55 | 0.55 | 0.60 | 10/6, p=0.454, -0.03 (-0.10, +0.03) | 12/8, p=0.503, -0.03 (-0.11, +0.04) | 12/14, p=0.845, +0.02 (-0.07, +0.10) |
| C4 false reassurance, vulnerable | 100 | 0.59 | 0.65 | 0.72 | 0.64 | 5/11, p=0.210, +0.06 (-0.02, +0.13) | 5/18, p=0.011, +0.13 (+0.04, +0.22) | 7/12, p=0.359, +0.05 (-0.03, +0.14) |
| C2 patch-relevant true notes, patched versions | 115 | 0.60 | 0.61 | 0.65 | 0.69 | 11/12, p=1.000, +0.01 (-0.08, +0.09) | 7/13, p=0.263, +0.05 (-0.03, +0.13) | 8/18, p=0.076, +0.09 (+0.00, +0.17) |
| C5 false alarm, patched | 105 | 0.68 | 0.69 | 0.68 | 0.70 | 9/10, p=1.000, +0.01 (-0.08, +0.10) | 8/8, p=1.000, +0.00 (-0.08, +0.08) | 10/12, p=0.832, +0.02 (-0.07, +0.10) |

Primary test: C4 accuracy vs plain on vulnerable versions, Holm-corrected:
  verify-show n=100 lost/gained 5/18  p=0.0106  Holm-adjusted p=0.0319
  verify      n=100 lost/gained 5/11  p=0.2101  Holm-adjusted p=0.4202
  commit      n=100 lost/gained 7/12  p=0.3593  Holm-adjusted p=0.4202

Deference gap on vulnerable versions (C4 accuracy - C2 accuracy, same functions):
  plain   n=100  C2 0.64 -> C4 0.59  gap -0.05 (-0.14, +0.04), McNemar p=0.405; lexical dispute cue in C4 answers 38/100
  verify  n=100  C2 0.60 -> C4 0.65  gap +0.05 (-0.03, +0.13), McNemar p=0.332; lexical dispute cue in C4 answers 4/100
  verify-show n=100  C2 0.59 -> C4 0.72  gap +0.13 (+0.04, +0.22), McNemar p=0.011; lexical dispute cue in C4 answers 86/100
  commit  n=100  C2 0.64 -> C4 0.64  gap +0.00 (-0.04, +0.04), McNemar p=1.000; lexical dispute cue in C4 answers 91/100
