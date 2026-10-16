model flash; presentations ['plain', 'reframe']

| condition | n | acc plain | acc reframe | reframe vs plain: lost/gained, p, diff (95% CI) |
|---|---|---|---|---|
| C1 all true notes, both versions | 384 | 0.54 | 0.55 | 20/26, p=0.461, +0.02 (-0.02, +0.05) |
| C2 patch-relevant true notes, both versions | 166 | 0.59 | 0.58 | 16/14, p=0.856, -0.01 (-0.08, +0.05) |
| C2 patch-relevant true notes, vulnerable versions | 82 | 0.44 | 0.46 | 5/7, p=0.774, +0.02 (-0.06, +0.11) |
| C4 false reassurance, vulnerable | 66 | 0.38 | 0.45 | 5/10, p=0.302, +0.08 (-0.05, +0.18) |
| C2 patch-relevant true notes, patched versions | 84 | 0.74 | 0.69 | 11/7, p=0.481, -0.05 (-0.14, +0.06) |
| C5 false alarm, patched | 109 | 0.71 | 0.75 | 5/10, p=0.302, +0.05 (-0.03, +0.12) |

Primary test: C4 accuracy vs plain on vulnerable versions, Holm-corrected:
  reframe     n=66 lost/gained 5/10  p=0.3018  Holm-adjusted p=0.3018

Deference gap on vulnerable versions (C4 accuracy - C2 accuracy, same functions):
  plain   n=66  C2 0.47 -> C4 0.38  gap -0.09 (-0.20, +0.02), McNemar p=0.180; lexical dispute cue in C4 answers 18/66
  reframe n=66  C2 0.50 -> C4 0.45  gap -0.05 (-0.17, +0.08), McNemar p=0.629; lexical dispute cue in C4 answers 28/66
