model flash; presentations ['plain', 'quote', 'alarms', 'reframe', 'provenance']

| condition | n | acc plain | acc quote | acc alarms | acc reframe | acc provenance | quote vs plain: lost/gained, p, diff (95% CI) | alarms vs plain: lost/gained, p, diff (95% CI) | reframe vs plain: lost/gained, p, diff (95% CI) | provenance vs plain: lost/gained, p, diff (95% CI) |
|---|---|---|---|---|---|---|---|---|---|---|
| C1 all true notes, both versions | 374 | 0.59 | 0.59 | 0.59 | 0.61 | 0.58 | 32/29, p=0.798, -0.01 (-0.05, +0.03) | 30/30, p=1.000, +0.00 (-0.04, +0.04) | 21/27, p=0.471, +0.02 (-0.02, +0.05) | 25/19, p=0.451, -0.02 (-0.05, +0.02) |
| C2 patch-relevant true notes, both versions | 189 | 0.68 | 0.66 | 0.65 | 0.66 | 0.68 | 18/15, p=0.728, -0.02 (-0.07, +0.04) | 17/11, p=0.345, -0.03 (-0.08, +0.02) | 20/16, p=0.618, -0.02 (-0.08, +0.04) | 7/7, p=1.000, +0.00 (-0.04, +0.04) |
| C2 patch-relevant true notes, vulnerable versions | 96 | 0.69 | 0.64 | 0.58 | 0.64 | 0.65 | 10/5, p=0.302, -0.05 (-0.14, +0.03) | 13/3, p=0.021, -0.10 (-0.19, -0.03) | 10/5, p=0.302, -0.05 (-0.14, +0.02) | 4/0, p=0.125, -0.04 (-0.08, -0.01) |
| C4 false reassurance, vulnerable | 83 | 0.64 | 0.75 | 0.67 | 0.82 | 0.65 | 4/13, p=0.049, +0.11 (+0.02, +0.20) | 6/9, p=0.607, +0.04 (-0.06, +0.13) | 1/16, p=0.000, +0.18 (+0.10, +0.28) | 6/7, p=1.000, +0.01 (-0.07, +0.10) |
| C2 patch-relevant true notes, patched versions | 93 | 0.67 | 0.69 | 0.71 | 0.68 | 0.71 | 8/10, p=0.815, +0.02 (-0.06, +0.12) | 4/8, p=0.388, +0.04 (-0.02, +0.12) | 10/11, p=1.000, +0.01 (-0.09, +0.11) | 3/7, p=0.344, +0.04 (-0.02, +0.11) |
| C5 false alarm, patched | 97 | 0.76 | 0.75 | 0.76 | 0.73 | 0.79 | 9/8, p=1.000, -0.01 (-0.09, +0.07) | 6/6, p=1.000, +0.00 (-0.07, +0.07) | 8/5, p=0.581, -0.03 (-0.10, +0.04) | 3/6, p=0.508, +0.03 (-0.03, +0.09) |

Primary test: C4 accuracy vs plain on vulnerable versions, Holm-corrected:
  reframe     n=83 lost/gained 1/16  p=0.0003  Holm-adjusted p=0.0011
  quote       n=83 lost/gained 4/13  p=0.0490  Holm-adjusted p=0.1471
  alarms      n=83 lost/gained 6/9  p=0.6072  Holm-adjusted p=1.0000
  provenance  n=83 lost/gained 6/7  p=1.0000  Holm-adjusted p=1.0000

Deference gap on vulnerable versions (C4 accuracy - C2 accuracy, same functions):
  plain   n=83  C2 0.75 -> C4 0.64  gap -0.11 (-0.18, -0.04), McNemar p=0.012; lexical dispute cue in C4 answers 23/83
  quote   n=83  C2 0.70 -> C4 0.75  gap +0.05 (-0.04, +0.14), McNemar p=0.454; lexical dispute cue in C4 answers 71/83
  alarms  n=83  C2 0.64 -> C4 0.67  gap +0.04 (-0.05, +0.12), McNemar p=0.581; lexical dispute cue in C4 answers 0/83
  reframe n=83  C2 0.67 -> C4 0.82  gap +0.14 (+0.06, +0.24), McNemar p=0.004; lexical dispute cue in C4 answers 57/83
  provenance n=83  C2 0.71 -> C4 0.65  gap -0.06 (-0.14, +0.01), McNemar p=0.227; lexical dispute cue in C4 answers 35/83
