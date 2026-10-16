# Pre-registration H3: multi-vendor replication of directional deference

Registered 2026-10-15, before any of the models below was run on any data of this project.
The analysis code (`sgv/direction.py`) was written and run on the four earlier models before this file was
written; it is not changed for H3.

## Background (exploratory, from the four earlier configurations)

Accuracy contrasts made deference look model-dependent, because models that flag most functions cannot be pushed
further towards VULNERABLE. A direction-aware measure (below) gave, for deepseek-chat, deepseek-flash (R),
deepseek-v4-pro (R) and qwen-plus, asymmetries of +0.18, +0.11, +0.14 and +0.09 (pooled +0.13, 95% CI +0.04 to
+0.22). These four models generated the hypothesis and are not part of the confirmatory test.

We also checked and rejected a different post-hoc idea (models follow evidence congruent with their leaning):
flip rates conditioned on the baseline verdict are dominated by regression to the mean (neutral perturbations such as
C0 -> C3 produce similar or larger flips), so that analysis is not used.

## Models (new; Alibaba Bailian, OpenAI-compatible endpoint, thinking disabled, temperature 0, max 8000 tokens)

| name | API model | vendor |
|---|---|---|
| glm-5.2 | glm-5.2 | Zhipu AI |
| kimi-k2.6 | kimi-k2.6 | Moonshot AI |
| kimi-k3 | kimi-k3 | Moonshot AI |
| qwen3.7-plus | qwen3.7-plus-2026-05-26 | Alibaba |
| qwen3.7-max | qwen3.7-max-2026-06-08 | Alibaba |
| qwen3.7-flash | qwen3.7-flash-2026-07-15 | Alibaba |
| ds-v4.1-flash | deepseek-v4.1-flash | DeepSeek |

## Data and conditions

Study set (187 PrimeVul pairs, `python -m sgv.evidence --pairs 0`), plain presentation, conditions C2, C4, C5.
Output: `results/h3_<model>`. Same prompts as all earlier runs.

## Measures

Per model, on pairs where both conditions exist:
- assurance shift = share SAFE under C4 minus share SAFE under C2, vulnerable versions;
- alarm shift = share VULNERABLE under C5 minus share VULNERABLE under C2, patched versions;
- asymmetry = assurance shift minus alarm shift.

## Hypothesis and test

**H3 (primary).** False assurances move verdicts towards their claim more than false alarms do: the mean asymmetry
over the seven new models is greater than 0. Test: bootstrap over pairs, resampled jointly for all models (2,000
resamples, seed 0), one-sided, alpha = 0.05; we also report the two-sided 95% CI.
Command: `python -m sgv.direction results/h3_* --models glm-5.2,kimi-k2.6,kimi-k3,qwen3.7-plus,qwen3.7-max,qwen3.7-flash,ds-v4.1-flash --pooled`

**Secondary (reported, not used to decide H3).** Number of models with positive asymmetry (one-sided sign test);
per-model accuracy contrasts C4 vs C2 and C5 vs C2 (`sgv.contrasts`); lexical dispute rates in C4 vs C5.
Any relation between a model's leaning and its shifts is exploratory.

## Missing data

API failures are missing data. If a model cannot complete (quota, deprecation), it is reported as such and H3 is
evaluated on the models that completed; no model is dropped for any other reason. Runs are not repeated to obtain
different results.
