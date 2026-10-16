# Trusting the Tool: Asymmetric Deference of LLM Vulnerability Auditors to Static-Analysis Evidence

Replication package for the paper of the same title by ZhiHong Liu.

LLM vulnerability auditors were given static-analysis evidence about vulnerable and patched C/C++ functions from
PrimeVul. The evidence was either true or fabricated, while the code and the model stayed fixed. False *assurances*
(a missing check is claimed to exist) lowered the detection of real vulnerabilities. False *alarms* (an added check
is claimed to be missing) never lowered accuracy, and models disputed them far more often. A registered replication
on seven new models confirmed the asymmetry. Verifying each claim in a separate call and showing the refuted claims
(*verify-show*) reduced deference in a registered test.

This repository contains the analyser, the experiment and analysis code, the registrations, the annotations and the
summary reports. The full run records (every evidence note and model response) and the LLM response cache are
archived separately (see [Full results](#full-results)).

## Contents

| Path | Content |
|---|---|
| `sgv/cfront.py` | Intraprocedural C/C++ front end (tree-sitter): sensitive operations, dominating guards, proof obligations |
| `sgv/evidence.py` | The controlled study: evidence conditions C0–C5, presentation strategies, model configurations, runner |
| `sgv/vuln.py` | Audit prompt, verdict parsing and PrimeVul loading (also the preliminary vulnerability study) |
| `sgv/contrasts.py` | Per-version accuracies and matched contrasts (C4 vs C2, C5 vs C2, …) |
| `sgv/direction.py` | Direction-aware deference measure (H3) |
| `sgv/deference.py` | Deference and the lexical "dispute" cue |
| `sgv/mitigation.py` | Comparison of presentation strategies with paired McNemar tests and Holm correction |
| `sgv/pooled.py` | Post-hoc pooled analysis of H2 and dataset descriptives |
| `sgv/annotate.py` | Annotation sheets and agreement (Cohen's kappa) for the behavioural coding |
| `sgv/figures.py`, `sgv/diagrams.py` | All figures of the paper, computed from the run records |
| `sgv/stats.py` | Wilson intervals, exact McNemar test, paired bootstrap |
| `sgv/llm.py` | OpenAI-compatible client with an SQLite response cache |
| `sgv/analysis.py`, `claims.py`, `verifier.py`, `methods.py`, `run.py`, `trace.py`, `labeling.py`, … | Preliminary study on Python (CRUXEval, REval): claim extraction and structure-grounded verification |
| `preregistration/` | Registration of H3 and the hashes of the analysis code fixed before the runs |
| `annotation/` | Annotation guide, sheets of both LLM annotators, the author's 20-item check |
| `results/*.md` | Summary reports of the study, held-out, development, test and H3 sets |
| `tests/` | Unit tests (`python -m unittest discover -s tests -t .`) |

## Setup

Python 3.12 or later (developed with 3.14).

```bash
pip install -r requirements.txt
```

### Data

PrimeVul is not redistributed here. Download the paired splits from the
[PrimeVul repository](https://github.com/DLVulDet/PrimeVul) and place them as

```
data/primevul/primevul_train_paired.jsonl
data/primevul/primevul_valid_paired.jsonl
data/primevul/primevul_test_paired.jsonl
```

Pair selection is deterministic given the file, `--pairs`, `--max-lines` and `--seed`. The data for the preliminary
study are downloaded by `python -m sgv.data --dest data/cruxeval.jsonl` and `python -m sgv.reval --dest data/reval`.

## Full results

The full results directory, with `evidence.jsonl` (the notes shown under every condition) and `records.jsonl` (every
model response and verdict) for each run, together with `llm_cache.sqlite` (all API responses), is archived on
Zenodo. Unzip it in the repository root so that it creates `results/`. With the cache in place, every run below
replays from the cache without any API call, and every analysis reproduces the numbers of the paper.

## Reproducing the analyses (no API access needed)

```bash
python -m sgv.contrasts results/evidence_full_a                    # RQ1/RQ2 on the study set
python -m sgv.deference results/evidence_full_a                    # RQ3: deference and dispute cue
python -m sgv.mitigation results/evidence_full_a results/mitig_quote results/mitig_alarms \
       results/mitig_reframe results/mitig_provenance --model flash  # RQ4 on the study set
python -m sgv.direction results/h3_* --pooled                      # H3 (registered)
python -m sgv.pooled                                               # post-hoc pooled H2
python -m sgv.annotate score annotation/sheet_claude.csv annotation/sheet_deepseek.csv
python -m sgv.figures --out figures                                # data figures
python -m sgv.diagrams --out figures                               # schematic figures
```

## Running the experiments

The models are called through OpenAI-compatible APIs (DeepSeek and Alibaba Cloud Bailian/DashScope). Model names,
pinned snapshots and request settings are in `MODELS` in `sgv/evidence.py`. API keys are read from the environment
(`SGV_API_KEY` for DeepSeek, `SGV_QWEN_KEY` for DashScope) or from `~/.sgv_deepseek_key` / `~/.sgv_qwen_key`.
They are never written to the repository.

```bash
# Build and inspect the evidence of every condition without calling a model
python -m sgv.evidence --pairs 0 --dry-run --out results/evidence_dry

# One run: conditions, presentation strategy and models are arguments
python -m sgv.evidence --data data/primevul/primevul_test_paired.jsonl --pairs 0 \
       --models flash --conditions C2,C4,C5 --presentation plain --out results/my_run
```

Main options: `--conditions` (C0–C5), `--presentation` (`plain`, `quote`, `alarms`, `reframe`, `provenance`,
`verify`, `verify-show`, `commit`, `commit-verify`), `--heldout` (pairs disjoint from the study set),
`--max-lines`, `--seed`. The data sets of the paper are

| Set | Source split | Selection |
|---|---|---|
| Study | `primevul_test_paired` | structural CWEs, ≤150 lines, all eligible pairs |
| Held-out | `primevul_test_paired` | `--heldout --max-lines 300` (all CWEs, disjoint from the study set) |
| Development | `primevul_valid_paired` | all eligible pairs |
| Test (registered) | `primevul_train_paired` | `--pairs 300 --seed 7` |

`run_h3.ps1` runs the registered H3 replication (seven models, C2/C4/C5, plain presentation).

## Notes on annotation

The behavioural coding was annotated by two LLMs (Claude and `deepseek-v4-pro`). The author checked 20 items by hand.
The paper reports this.

## License

Code: MIT (see `LICENSE`). PrimeVul and the preliminary-study data sets keep their own licenses.

## Citation

```bibtex
@misc{liu2026trusting,
  title  = {Trusting the Tool: Asymmetric Deference of {LLM} Vulnerability Auditors to Static-Analysis Evidence},
  author = {Liu, ZhiHong},
  year   = {2026},
  note   = {Preprint}
}
```
