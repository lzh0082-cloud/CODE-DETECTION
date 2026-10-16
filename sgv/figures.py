"""Data figures of the paper, computed from the run records (never typed in by hand).

    python -m sgv.figures [--out paper/figures]

Writes vector PDFs:
  conditions.pdf    accuracy per evidence condition and version (RQ1/RQ2, descriptive)
  asymmetry.pdf     matched contrasts: false assurance (C4 vs C2) and false alarm (C5 vs C2) per model (RQ2)
  scrutiny.pdf      how often answers reject the false note: lexical cue per model, annotated rates (RQ3)
  design_space.pdf  effect of every presentation strategy on C4 and on C2, phase by phase (RQ4)
Models or runs that are missing are skipped, so the script can be rerun as runs complete.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .deference import disputes  # noqa: E402
from .stats import bootstrap_diff, mcnemar_exact, wilson  # noqa: E402

RESULTS = "results"
LABEL = {"flash": "deepseek-chat", "flash-think": "deepseek-flash (R)", "pro-think": "deepseek-v4-pro (R)$^\\dagger$",
         "qwen-plus": "qwen-plus"}
# Okabe-Ito, distinguishable for colour-blind readers and in greyscale by marker
COLOR = {"flash": "#0072B2", "flash-think": "#E69F00", "pro-think": "#009E73", "qwen-plus": "#CC79A7"}
MARKER = {"flash": "o", "flash-think": "s", "pro-think": "D", "qwen-plus": "^"}
FALSE_ASSURANCE, FALSE_ALARM = "#D55E00", "#56B4E9"
MUTED = "#666666"

# where each model's study-set runs live
STUDY = {"flash": ["evidence_full_a"], "flash-think": ["evidence_full_a"], "pro-think": ["evidence_pilot_b"],
         "qwen-plus": ["qwen_study_c245", "qwen_study_c01"]}
EXPLORATORY = ["flash", "flash-think", "pro-think", "qwen-plus"]
# multi-vendor replication registered as H3 (preregistration/H3_multimodel.md)
H3 = ["glm-5.2", "kimi-k2.6", "kimi-k3", "qwen3.7-plus", "qwen3.7-max", "qwen3.7-flash", "ds-v4.1-flash"]
VENDOR_COLOR = {"deepseek": "#0072B2", "qwen": "#CC79A7", "glm": "#009E73", "kimi": "#E69F00"}
for _m in H3:
    STUDY[_m] = [f"h3_{_m}"]
    LABEL[_m] = {"ds-v4.1-flash": "deepseek-v4.1-flash"}.get(_m, _m)
    COLOR[_m] = VENDOR_COLOR["deepseek" if _m.startswith("ds") else _m.split("-")[0].rstrip("3.7")]
    MARKER[_m] = "o"


def style() -> None:
    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["STIXGeneral", "Times New Roman", "DejaVu Serif"],
        "mathtext.fontset": "stix", "font.size": 8, "axes.titlesize": 8.5, "axes.labelsize": 8,
        "xtick.labelsize": 7.5, "ytick.labelsize": 7.5, "legend.fontsize": 7, "axes.spines.top": False,
        "axes.spines.right": False, "axes.linewidth": 0.6, "xtick.major.width": 0.6, "ytick.major.width": 0.6,
        "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02})


def load(*dirs: str) -> dict:
    """(model, presentation, condition, pair_id, target) -> record; API failures are dropped."""
    R = {}
    for d in dirs:
        path = os.path.join(RESULTS, d, "records.jsonl")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                if not r.get("error"):
                    R[(r["model"], r.get("presentation", "plain"), r["condition"], r["pair_id"], r["target"])] = r
    return R


def paired(R: dict, model: str, a: tuple[str, str], b: tuple[str, str], target: int):
    """Accuracy of (presentation, condition) b minus a on the shared functions of one version."""
    keys = sorted({(k[3], k[4]) for k in R if k[0] == model and k[1:3] == a and k[4] == target})
    keys = [k for k in keys if (model, *b, *k) in R]
    if not keys:
        return None
    xa = [bool(R[(model, *a, *k)]["correct"]) for k in keys]
    xb = [bool(R[(model, *b, *k)]["correct"]) for k in keys]
    lo, hi = bootstrap_diff(xa, xb)
    lost = sum(1 for u, v in zip(xa, xb) if u and not v)
    gained = sum(1 for u, v in zip(xa, xb) if v and not u)
    return {"n": len(keys), "diff": (sum(xb) - sum(xa)) / len(keys), "lo": lo, "hi": hi,
            "p": mcnemar_exact(lost, gained)}


def stars(p: float) -> str:
    return "***" if p < .001 else "**" if p < .01 else "*" if p < .05 else ""


# --------------------------------------------------------------------------------------------- RQ1 / RQ2

def fig_conditions(models: list[str], out: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.4), sharey=True)
    panels = [(1, "Vulnerable versions (correct = VULNERABLE)", ["C0", "C1", "C2", "C3", "C4"]),
              (0, "Patched versions (correct = SAFE)", ["C0", "C1", "C2", "C3", "C5"])]
    # pro-think ran on a 60-pair subset only; the H3 models only on C2/C4/C5
    shown = [m for m in models if m in ("flash", "flash-think", "qwen-plus")]
    for ax, (target, title, conds) in zip(axes, panels):
        for i, m in enumerate(shown):
            R = load(*STUDY[m])
            xs, ys, err = [], [], [[], []]
            for j, c in enumerate(conds):
                rows = [r for k, r in R.items() if k[0] == m and k[2] == c and k[4] == target]
                if not rows:
                    continue
                k = sum(bool(r["correct"]) for r in rows)
                lo, hi = wilson(k, len(rows))
                xs.append(j + (i - (len(shown) - 1) / 2) * 0.16)
                ys.append(k / len(rows))
                err[0].append(k / len(rows) - lo)
                err[1].append(hi - k / len(rows))
            if xs:
                joined = "-" if len(xs) == len(conds) else ""  # no lines across conditions that were not run
                ax.errorbar(xs, ys, yerr=err, fmt=MARKER[m] + joined, color=COLOR[m], ms=4, lw=0.8, elinewidth=0.8,
                            capsize=1.5, label=LABEL[m])
        ax.axvspan(len(conds) - 1.5, len(conds) - 0.5, color="#EEEEEE", zorder=0)
        ax.text(len(conds) - 1, 0.03, "false\nevidence", ha="center", va="bottom", fontsize=6.5, color="#555555")
        ax.set_xticks(range(len(conds)))
        ax.set_xticklabels(conds)
        ax.set_xlim(-0.5, len(conds) - 0.5)
        ax.set_ylim(0, 1.02)
        ax.set_title(title)
        ax.grid(axis="y", lw=0.4, color="#DDDDDD")
    axes[0].set_ylabel("Accuracy (95% Wilson CI)")
    axes[0].legend(loc="lower left", frameon=False)
    fig.savefig(os.path.join(out, "conditions.pdf"))
    plt.close(fig)


def fig_asymmetry(models: list[str], out: str) -> None:
    rows = []
    for m in models:
        R = load(*STUDY[m])
        c4 = paired(R, m, ("plain", "C2"), ("plain", "C4"), 1)
        c5 = paired(R, m, ("plain", "C2"), ("plain", "C5"), 0)
        if c4 or c5:
            rows.append((m, c4, c5))
    fig, ax = plt.subplots(figsize=(3.5, 0.55 + 0.42 * len(rows)))
    n_exp = sum(m in EXPLORATORY for m, *_ in rows)
    if 0 < n_exp < len(rows):
        ax.axhline(len(rows) - n_exp - 0.5, color="#BBBBBB", lw=0.5, ls="--")
        ax.text(0.47, len(rows) - n_exp - 0.42, "exploratory", ha="right", va="bottom", fontsize=6, color=MUTED)
        ax.text(0.47, len(rows) - n_exp - 0.58, "replication (H3)", ha="right", va="top", fontsize=6, color=MUTED)
    for i, (m, c4, c5) in enumerate(rows):
        y = len(rows) - 1 - i
        for res, dy, col, mk in ((c4, 0.12, FALSE_ASSURANCE, "o"), (c5, -0.12, FALSE_ALARM, "s")):
            if not res:
                continue
            ax.errorbar(res["diff"], y + dy, xerr=[[res["diff"] - res["lo"]], [res["hi"] - res["diff"]]],
                        fmt=mk, color=col, ms=4, elinewidth=1, capsize=1.5)
            ax.text(res["hi"] + 0.012, y + dy, f"{res['diff']:+.2f}{stars(res['p'])}", va="center", fontsize=6.5,
                    color=col)
    ax.axvline(0, color="#444444", lw=0.6)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([LABEL[m] for m, *_ in reversed(rows)])
    ax.set_xlabel("Accuracy change vs. true evidence on the same operations")
    ax.set_xlim(-0.42, 0.48)
    ax.plot([], [], "o", color=FALSE_ASSURANCE, label="false assurance (C4 $-$ C2, vulnerable)")
    ax.plot([], [], "s", color=FALSE_ALARM, label="false alarm (C5 $-$ C2, patched)")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=1, frameon=False)
    ax.grid(axis="x", lw=0.4, color="#DDDDDD")
    fig.savefig(os.path.join(out, "asymmetry.pdf"))
    plt.close(fig)


# --------------------------------------------------------------------------------------------- RQ3

def _annotated_rates(sheet: str, key: str, population: dict, iters: int = 2000) -> dict:
    """Rate of answers rejecting the false note per condition, reweighting the cue strata to the population."""
    cue = {int(r["item"]): r for r in csv.DictReader(open(key, encoding="utf-8-sig"))}
    lab = {int(r["item"]): r["rejects_false_note"].strip().upper()
           for r in csv.DictReader(open(sheet, encoding="utf-8-sig"))}
    res = {}
    rng = random.Random(0)
    for cond in ("C4", "C5"):
        strata = {s: [lab[i] == "Y" for i, k in cue.items() if k["condition"] == cond and k["cue_disputes"] == s
                      and lab.get(i) in ("Y", "N")] for s in ("1", "0")}
        w = population[cond]  # share of cue-flagged answers in the population

        def rate(st):
            return w * sum(st["1"]) / len(st["1"]) + (1 - w) * sum(st["0"]) / len(st["0"])

        boots = sorted(rate({s: [rng.choice(v) for _ in v] for s, v in strata.items()}) for _ in range(iters))
        res[cond] = (rate(strata), boots[int(0.025 * iters)], boots[int(0.975 * iters)])
    return res


def fig_scrutiny(models: list[str], out: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.6), gridspec_kw={"width_ratios": [2.2, 1]})
    ax = axes[0]
    shown = []
    for m in models:
        R = load(*STUDY[m])
        vals = {}
        for c in ("C4", "C5"):
            rows = [r for k, r in R.items() if k[0] == m and k[1] == "plain" and k[2] == c]
            if rows:
                vals[c] = (sum(disputes(r["reasoning"]) for r in rows), len(rows))
        if len(vals) == 2:
            shown.append((m, vals))
    for i, (m, vals) in enumerate(shown):
        for c, dx, col in (("C4", -0.18, FALSE_ASSURANCE), ("C5", 0.18, FALSE_ALARM)):
            k, n = vals[c]
            lo, hi = wilson(k, n)
            ax.bar(i + dx, k / n, 0.34, color=col, alpha=0.85 if m in EXPLORATORY else 1.0, edgecolor="none",
                   hatch=None if m in EXPLORATORY else None)
            ax.errorbar(i + dx, k / n, yerr=[[k / n - lo], [hi - k / n]], color="#333333", lw=0.8, capsize=1.5)
    ax.set_xticks(range(len(shown)))
    ax.set_xticklabels([LABEL[m] for m, _ in shown], fontsize=6.3, rotation=35, ha="right")
    n_exp = sum(m in EXPLORATORY for m, _ in shown)
    if 0 < n_exp < len(shown):
        ax.axvline(n_exp - 0.5, color="#BBBBBB", lw=0.5, ls="--")
    ax.set_ylim(0, 1)
    ax.set_ylabel("Answers disputing a note")
    ax.set_title("(a) Lexical dispute cue, all answers (lower bound)")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=FALSE_ASSURANCE, alpha=0.85, label="false assurance (C4)"),
                       Patch(color=FALSE_ALARM, alpha=0.85, label="false alarm (C5)")],
              loc="upper center", ncol=2, frameon=False)
    ax.grid(axis="y", lw=0.4, color="#DDDDDD")

    # (b) annotated rates, reweighted to the population the sample was drawn from
    R = load("evidence_full_a", "evidence_pilot_b")
    population = {}
    for c in ("C4", "C5"):
        rows = [r for k, r in R.items() if k[2] == c and r["reasoning"].strip()]
        population[c] = sum(disputes(r["reasoning"]) for r in rows) / len(rows)
    ax = axes[1]
    for j, (name, sheet) in enumerate((("Claude", "annotation/sheet_claude.csv"),
                                       ("DeepSeek-v4-pro", "annotation/sheet_deepseek.csv"))):
        if not os.path.exists(sheet):
            continue
        rates = _annotated_rates(sheet, "annotation/key.csv", population)
        for c, dx, col in (("C4", -0.18, FALSE_ASSURANCE), ("C5", 0.18, FALSE_ALARM)):
            v, lo, hi = rates[c]
            ax.bar(j + dx, v, 0.34, color=col, alpha=0.85, edgecolor="none")
            ax.errorbar(j + dx, v, yerr=[[v - lo], [hi - v]], color="#333333", lw=0.8, capsize=1.5)
            ax.text(j + dx, hi + 0.02, f"{v:.2f}", ha="center", fontsize=6.5)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["annotator 1\n(Claude)", "annotator 2\n(deepseek-v4-pro)"], fontsize=7)
    ax.set_ylim(0, 1)
    ax.set_ylabel("Answers rejecting the false note")
    ax.set_title("(b) Annotated, reweighted (95% bootstrap CI)")
    ax.grid(axis="y", lw=0.4, color="#DDDDDD")
    fig.tight_layout(w_pad=2)
    fig.savefig(os.path.join(out, "scrutiny.pdf"))
    plt.close(fig)


def fig_direction(models: list[str], out: str) -> None:
    """Shift towards the claim of false evidence, per model, with the pooled estimate of each group (H3)."""
    from .direction import load as dload, stat, units
    groups = [("Exploratory (hypothesis-generating)", [m for m in EXPLORATORY if m in models]),
              ("Registered replication (H3)", [m for m in H3 if m in models])]
    rng = random.Random(0)
    rows = []  # (label, colour, shift_a, ci_a, shift_l, ci_l, asym, ci, is_pooled)
    for title, ms in groups:
        U = {}
        for m in ms:
            R = dload([os.path.join(RESULTS, d) for d in STUDY[m] if os.path.exists(os.path.join(RESULTS, d))])
            if (u := units(R, m)):
                U[m] = u
        if not U:
            continue
        rows.append((title, None))
        for m, u in U.items():
            pids = sorted(u)
            boots = [stat(u, [rng.choice(pids) for _ in pids]) for _ in range(2000)]
            rows.append((m, (stat(u, pids), [sorted(b[i] for b in boots) for i in range(3)])))
        pids = sorted(set().union(*U.values()))

        def pooled(sample):
            vals = [stat(U[m], sample) for m in U]
            return tuple(sum(v[i] for v in vals) / len(vals) for i in range(3))

        boots = [pooled([rng.choice(pids) for _ in pids]) for _ in range(2000)]
        rows.append((f"pooled ({len(U)} models)", (pooled(pids), [sorted(b[i] for b in boots) for i in range(3)])))
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 0.45 + 0.2 * len(rows)), sharey=True,
                             gridspec_kw={"width_ratios": [1.25, 1]})
    lo, hi = 49, 1949
    ys = list(range(len(rows) - 1, -1, -1))
    labels = []
    for y, (name, res) in zip(ys, rows):
        if res is None:
            labels.append(name)
            for ax in axes:
                ax.axhline(y - 0.5 + 1, color="#BBBBBB", lw=0.5, ls="--") if y != ys[0] else None
            continue
        (sa, sl, d), ci = res
        pooled_row = name.startswith("pooled")
        labels.append(name if pooled_row else LABEL[name])
        col = "#222222" if pooled_row else COLOR[name]
        mk = "D" if pooled_row else MARKER[name]
        for val, c, dy, colr, m2 in ((sa, ci[0], 0.13, FALSE_ASSURANCE, "o"), (sl, ci[1], -0.13, FALSE_ALARM, "s")):
            axes[0].errorbar(val, y + dy, xerr=[[val - c[lo]], [c[hi] - val]], fmt=m2, color=colr, ms=3.2,
                             elinewidth=0.9, capsize=1.2)
        axes[1].errorbar(d, y, xerr=[[d - ci[2][lo]], [ci[2][hi] - d]], fmt=mk, color=col, ms=5 if pooled_row else 4,
                         elinewidth=1.4 if pooled_row else 0.9, capsize=1.5)
        axes[1].text(0.99, y, f"{d:+.2f}", ha="right", va="center", fontsize=6.4,
                     weight="bold" if pooled_row else "normal", transform=axes[1].get_yaxis_transform())
    axes[0].set_yticks(ys)
    axes[0].set_yticklabels(labels, fontsize=6.8)
    for t, (name, res) in zip(axes[0].get_yticklabels(), rows):
        if res is None:
            t.set_fontweight("bold")
            t.set_fontsize(7)
        elif name.startswith("pooled"):
            t.set_fontstyle("italic")
    for ax, title in ((axes[0], "Shift towards the claim of the false note"),
                      (axes[1], "Asymmetry (assurance $-$ alarm)")):
        ax.axvline(0, color="#444444", lw=0.6)
        ax.grid(axis="x", lw=0.4, color="#DDDDDD")
        ax.set_title(title)
    axes[0].set_ylim(-0.6, len(rows) - 0.4)
    axes[0].set_xlim(-0.35, 0.4)
    axes[1].set_xlim(-0.3, 0.6)
    axes[0].plot([], [], "o", color=FALSE_ASSURANCE, label="false assurance: share SAFE, C4 $-$ C2")
    axes[0].plot([], [], "s", color=FALSE_ALARM, label="false alarm: share VULNERABLE, C5 $-$ C2")
    axes[0].legend(loc="upper center", bbox_to_anchor=(0.45, -0.04 - 0.6 / len(rows)), ncol=2, frameon=False,
                   fontsize=6.5)
    fig.savefig(os.path.join(out, "direction.pdf"))
    plt.close(fig)


# --------------------------------------------------------------------------------------------- RQ4

PHASES = [  # (phase label, plain run dirs, [(strategy, run dirs)], model)
    ("Study set\n(exploratory)", ["evidence_full_a"],
     [("quote", ["mitig_quote"]), ("alarms", ["mitig_alarms"]), ("reframe", ["mitig_reframe"]),
      ("provenance", ["mitig_provenance"])], "flash"),
    ("Held-out\n(replication)", ["confirm_plain"], [("reframe", ["confirm_reframe"])], "flash"),
    ("Development", ["dev_plain"],
     [("verify", ["dev_verify"]), ("verify-show", ["dev_verify_show"]), ("commit", ["dev_commit"]),
      ("commit-verify", ["dev_commit_verify_c4", "dev_commit_verify_c1"])], "flash"),
    ("Test\n(registered)", ["test_flash_plain"], [("verify-show", ["test_flash_verifyshow"])], "flash"),
    ("Test\n(registered)", ["test_qwen_plain"], [("verify-show", ["test_qwen_verifyshow"])], "qwen-plus"),
]


def fig_design_space(out: str, models: list[str]) -> None:
    rows = []  # (phase, strategy, model, C4 result, C2 result)
    for phase, base, strategies, model in PHASES:
        if model not in models:
            continue
        for name, dirs in strategies:
            R = load(*base, *dirs)
            c4 = paired(R, model, ("plain", "C4"), (name, "C4"), 1)
            c2 = paired(R, model, ("plain", "C2"), (name, "C2"), 1)
            if c4:
                rows.append((phase, name, model, c4, c2))
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 0.5 + 0.27 * len(rows)), sharey=True,
                             gridspec_kw={"width_ratios": [1.25, 1]})
    ys = list(range(len(rows) - 1, -1, -1))
    for ax, idx, title in ((axes[0], 3, "False assurance (C4): accuracy change vs. plain"),
                           (axes[1], 4, "True relevant evidence (C2): accuracy change vs. plain")):
        for y, row in zip(ys, rows):
            res, model = row[idx], row[2]
            if not res:
                ax.text(0, y, "not run", ha="center", va="center", fontsize=6.5, color="#888888")
                continue
            confirmed = row[0].startswith("Test")
            col = COLOR[model]
            ax.errorbar(res["diff"], y, xerr=[[res["diff"] - res["lo"]], [res["hi"] - res["diff"]]],
                        fmt=MARKER[model], color=col, mfc=col if confirmed else "white", ms=4.5, elinewidth=1,
                        capsize=1.5)
            ax.text(0.99, y, f"{res['diff']:+.2f}{stars(res['p'])}  (n={res['n']})", va="center", ha="right",
                    fontsize=6.3, color="#333333", transform=ax.get_yaxis_transform())
        ax.axvline(0, color="#444444", lw=0.6)
        ax.set_xlim(-0.3, 0.62)
        ax.set_title(title)
        ax.grid(axis="x", lw=0.4, color="#DDDDDD")
    # phase separators and labels
    prev = None
    for y, row in zip(ys, rows):
        key = (row[0], row[2])
        if prev is not None and key != prev:
            for ax in axes:
                ax.axhline(y + 0.5, color="#BBBBBB", lw=0.5, ls="--")
        prev = key
    axes[0].set_yticks(ys)
    axes[0].set_yticklabels([f"{r[1]}  [{r[0].splitlines()[0]}{', ' + LABEL[r[2]] if r[2] != 'flash' else ''}]"
                             for r in rows], fontsize=7)
    axes[0].set_ylim(-0.6, len(rows) - 0.4)
    axes[0].plot([], [], "o", color="#555555", mfc="white", label="exploratory (study / held-out / dev)")
    axes[0].plot([], [], "o", color="#555555", label="registered test, run once")
    axes[0].legend(loc="upper center", bbox_to_anchor=(0.9, -0.12 if len(rows) > 6 else -0.25), ncol=2,
                   frameon=False)
    fig.text(0.5, -0.01 - 0.12 / max(1, len(rows) / 6), "Paired difference in accuracy on vulnerable versions "
             "(95% bootstrap CI; * McNemar $p<.05$, ** $p<.01$, *** $p<.001$, uncorrected)", ha="center", fontsize=7)
    fig.savefig(os.path.join(out, "design_space.pdf"))
    plt.close(fig)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="paper/figures")
    ap.add_argument("--models", default=",".join(EXPLORATORY + H3))
    ap.add_argument("--preview", help="also write PNG copies to this directory")
    args = ap.parse_args(argv)
    models = args.models.split(",")
    os.makedirs(args.out, exist_ok=True)
    style()
    fig_conditions(models, args.out)
    fig_asymmetry(models, args.out)
    fig_scrutiny(models, args.out)
    fig_direction(models, args.out)
    fig_design_space(args.out, models)
    if args.preview:  # PNG copies for looking at the figures without a PDF viewer
        os.makedirs(args.preview, exist_ok=True)
        for fig_fn in (fig_conditions, fig_asymmetry, fig_scrutiny, fig_direction):
            _png(lambda d: fig_fn(models, d), args.preview)
        _png(lambda d: fig_design_space(d, models), args.preview)
    print(f"figures written to {args.out}")


def _png(draw, out: str) -> None:
    saved = plt.Figure.savefig
    plt.Figure.savefig = lambda self, path, **kw: saved(self, path.replace(".pdf", ".png"), dpi=200, **kw)
    try:
        draw(out)
    finally:
        plt.Figure.savefig = saved


if __name__ == "__main__":
    main()
