"""Schematic figures of the paper (study overview, verify-show, protocol), drawn with matplotlib so that the
PDF looks the same locally and on Overleaf. Numbers shown in the protocol figure are computed from the runs.

    python -m sgv.diagrams [--out paper/figures] [--preview DIR]
"""
from __future__ import annotations

import argparse
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

from .figures import FALSE_ALARM, FALSE_ASSURANCE, load, paired, stars, style  # noqa: E402

INK, MUTED, EDGE = "#222222", "#666666", "#9AA5B1"
FILL = {"data": "#EEF3F8", "tool": "#EAF4EC", "cond": "#FFF6E5", "pres": "#F3EEF8", "llm": "#F7EDED",
        "ana": "#F4F4F4", "good": "#E3F2E6", "bad": "#FBE7E3", "neutral": "#FFFFFF"}
MONO = {"family": "monospace", "fontsize": 6.3}


def canvas(w: float, h: float):
    fig = plt.figure(figsize=(w, h))
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, fill, title=None, lw=0.8, ls="-", edge=EDGE, radius=0.06):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={radius}", fc=FILL[fill],
                                ec=edge, lw=lw, ls=ls))
    if title:
        ax.text(x + w / 2, y + h - 0.07, title, ha="center", va="top", fontsize=7.6, weight="bold", color=INK)


def arrow(ax, p, q, ls="-", color="#555555", rad=0.0, lw=0.9):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=8, lw=lw, color=color, ls=ls,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1))


def pill(ax, x, y, text, color="#33475B"):
    ax.text(x, y, text, ha="center", va="center", fontsize=6.4, color="white", weight="bold",
            bbox=dict(boxstyle="round,pad=0.22,rounding_size=0.12", fc=color, ec="none"))


def lines(ax, x, y, rows, dy=0.135, **kw):
    """Left-aligned rows of (text, colour) or text."""
    default = kw.pop("color", INK)
    for i, row in enumerate(rows):
        text, col = row if isinstance(row, tuple) else (row, default)
        ax.text(x, y - i * dy, text, ha="left", va="top", color=col, **({"fontsize": 6.6} | kw))


# --------------------------------------------------------------------------------------------- overview

def overview(out: str) -> None:
    fig, ax = canvas(7.0, 2.85)
    top, h = 0.95, 1.75
    cols = [(0.05, 1.08, "data", "PrimeVul pair"), (1.33, 1.2, "tool", "Obligation analyser"),
            (2.78, 1.33, "cond", "Evidence condition"), (4.36, 1.2, "pres", "Presentation"),
            (5.81, 1.14, "llm", "LLM auditor")]
    for x, w, fill, title in cols:
        box(ax, x, top, w, h, fill, title)
    for (x1, w1, *_), (x2, *_) in zip(cols, cols[1:]):
        arrow(ax, (x1 + w1, top + h * 0.55), (x2, top + h * 0.55))

    # 1. data
    x = 0.12
    for k, (lab, col) in enumerate((("vulnerable version", FALSE_ASSURANCE), ("patched version", FALSE_ALARM))):
        yy = top + 1.25 - k * 0.5
        box(ax, x, yy - 0.12, 0.94, 0.36, "neutral", lw=0.6, radius=0.03)
        ax.text(x + 0.47, yy + 0.12, lab, ha="center", va="top", fontsize=6.4, color=col, weight="bold")
        for j in range(3):
            ax.plot([x + 0.08, x + 0.08 + (0.7, 0.55, 0.62)[j]], [yy - 0.0 - j * 0.045 + 0.0] * 2, color="#B8C2CC",
                    lw=1.2)
    ax.text(0.59, top + 0.2, "fix commit\n(used only to build\nthe conditions)", ha="center", va="center",
            fontsize=6, color=MUTED, style="italic")

    # 2. analyser
    lines(ax, 1.4, top + 1.5, ["tree-sitter, C/C++,", "intraprocedural", ""], fontsize=6.3, color=MUTED)
    lines(ax, 1.4, top + 1.12, ["sensitive operation", "  index, offset, deref,", "  free, size, division",
                                ("holds here:", "#1B7F3A"), "  dominating guards", ("concern:", "#B35900"),
                                "  what is not ensured"], dy=0.125, fontsize=6.3)

    # 3. conditions
    conds = [("C0", "no notes", INK), ("C1", "all, true", INK), ("C2", "patch-relevant, true", INK),
             ("C3", "irrelevant, true", INK), ("C4", "false assurance", FALSE_ASSURANCE),
             ("C5", "false alarm", FALSE_ALARM)]
    for i, (c, desc, col) in enumerate(conds):
        yy = top + 1.47 - i * 0.2
        ax.text(2.88, yy, c, fontsize=6.8, weight="bold", color=col, va="center")
        ax.text(3.12, yy, desc, fontsize=6.6, color=col, va="center")
    ax.text(3.445, top + 0.12, "same function, only the notes vary", ha="center", fontsize=5.9, color=MUTED,
            style="italic")

    # 4. presentation
    pres = ["plain", "quote", "alarms only", "reframe", "provenance", "verify", "verify-show", "commit",
            "commit-verify"]
    for i, p in enumerate(pres):
        yy = top + 1.5 - i * 0.152
        hl = p == "verify-show"
        ax.text(4.46, yy, p, fontsize=6.5, va="center", weight="bold" if hl else "normal",
                color="#5B2C83" if hl else INK)
    ax.text(5.5, top + 1.5 - 6 * 0.152, "final", fontsize=5.8, va="center", ha="right", color="white",
            bbox=dict(boxstyle="round,pad=0.15", fc="#5B2C83", ec="none"))

    # 5. auditor
    lines(ax, 5.88, top + 1.5, ["deepseek-chat", "deepseek-flash (R)", "deepseek-v4-pro (R)", "qwen-plus"],
          dy=0.14, fontsize=6.4)
    box(ax, 5.9, top + 0.12, 0.96, 0.62, "neutral", lw=0.6, radius=0.03)
    lines(ax, 5.95, top + 0.68, ["step-by-step", "reasoning ...", ""], dy=0.12, fontsize=6.1, color=MUTED)
    ax.text(5.95, top + 0.26, "[VERDICT]\nVULNERABLE | SAFE", fontsize=5.6, family="monospace",
            va="center", color=INK)

    # analysis band
    box(ax, 0.05, 0.08, 6.9, 0.62, "ana", None)
    ax.text(0.15, 0.6, "Analysis", fontsize=7.6, weight="bold", va="top")
    items = [("RQ1", "accuracy per version,\ntrue notes vs. none"),
             ("RQ2", "matched contrasts on the same\noperations: C4 vs C2, C5 vs C2"),
             ("RQ3", "disputes the note? lexical cue,\n2 LLM annotators + author check"),
             ("RQ4", "presentations vs. plain;\ndev $\\rightarrow$ frozen $\\rightarrow$ registered test")]
    for i, (rq, text) in enumerate(items):
        xx = 0.95 + i * 1.53
        pill(ax, xx, 0.39, rq)
        ax.text(xx + 0.2, 0.39, text, fontsize=6.0, va="center", color=INK)
    arrow(ax, (6.38, top), (6.38, 0.7))
    pill(ax, 3.445, top + h + 0.0, "RQ1  RQ2")
    pill(ax, 4.96, top + h + 0.0, "RQ4")
    pill(ax, 6.38, top + h + 0.0, "RQ3")
    fig.savefig(os.path.join(out, "overview.pdf"))
    plt.close(fig)


# --------------------------------------------------------------------------------------------- verify-show

def verify_show(out: str) -> None:
    fig, ax = canvas(7.0, 2.75)
    # code
    box(ax, 0.05, 1.3, 2.05, 1.38, "neutral", "Function (excerpt)")
    code = ["10  pps_id = gf_bs_read_ue(bs);", "11  if (pps_id > 255)", "12      return -1;",
            "13  pps = &avc->pps[pps_id];"]
    lines(ax, 0.12, 2.38, code, dy=0.17, **MONO)
    ax.text(1.075, 1.38, "pps_id is signed: a negative value\nreaches line 13 unchecked",
            ha="center", va="bottom", fontsize=5.9, color=MUTED, style="italic")
    # notes (C4)
    box(ax, 0.05, 0.08, 2.05, 1.12, "cond", "Analyser notes, C4 (false)")
    lines(ax, 0.12, 0.9, ["O1 [array index] line 13", ("  holds here: !(pps_id > 255)", "#1B7F3A"),
                          ("  pps_id >= 0 is checked before", FALSE_ASSURANCE),
                          ("  this access (line 12)", FALSE_ASSURANCE)], dy=0.16, **MONO)

    # call 1
    box(ax, 2.45, 1.3, 2.05, 1.38, "pres", "Call 1: verify each claim")
    lines(ax, 2.52, 2.4, ["Check every claim against the", "code only; quote the deciding", "line(s). CONFIRMED /",
                          "REFUTED / UNCLEAR."], dy=0.15, fontsize=6.5, style="italic", color=MUTED)
    box(ax, 2.45, 0.08, 2.05, 1.12, "neutral", "Verifier output")
    lines(ax, 2.52, 0.9, [("[1] CONFIRMED", "#1B7F3A"), "    \"if (pps_id > 255)\"", ("[2] REFUTED", FALSE_ASSURANCE),
                          "    \"12: return -1;\""], dy=0.16, **MONO)
    arrow(ax, (2.1, 2.0), (2.45, 2.0))
    arrow(ax, (2.1, 0.64), (2.45, 1.6), rad=-0.15)
    arrow(ax, (3.475, 1.3), (3.475, 1.2))

    # call 2
    box(ax, 4.85, 0.08, 2.1, 2.6, "llm", "Call 2: audit")
    lines(ax, 4.92, 2.4, ["code + confirmed notes", "+ claims the verifier refuted,", "shown separately:"], dy=0.15,
          fontsize=6.5, color=MUTED, style="italic")
    box(ax, 4.92, 1.18, 1.96, 0.68, "bad", None, lw=0.6, edge="#E3A79A", radius=0.03)
    lines(ax, 4.97, 1.8, ["Claims ... CONTRADICTED by the", "code (do not rely on them):", "- array index line 13 --",
                          "  pps_id >= 0 is checked ..."], dy=0.14, family="monospace", fontsize=5.6)
    lines(ax, 4.92, 1.02, ["... nothing prevents a negative", "pps_id from indexing pps[] ..."], dy=0.15,
          fontsize=6.3, color=MUTED, style="italic")
    ax.text(5.9, 0.33, "[VERDICT] VULNERABLE", ha="center", fontsize=6.8, family="monospace", weight="bold",
            color=FALSE_ASSURANCE)
    arrow(ax, (4.5, 0.64), (4.85, 1.5))
    arrow(ax, (4.5, 2.0), (4.85, 2.0))
    fig.savefig(os.path.join(out, "verify_show.pdf"))
    plt.close(fig)


# --------------------------------------------------------------------------------------------- protocol

def _effect(base, new, name, model="flash", cond="C4"):
    res = paired(load(*base, *new), model, ("plain", cond), (name, cond), 1)
    return res


def protocol(out: str) -> None:
    fig, ax = canvas(7.0, 1.86)
    W, gap, y0, h = 1.48, 0.33, 0.08, 1.72
    xs = [0.05 + i * (W + gap) for i in range(4)]

    study = _effect(["evidence_full_a"], ["mitig_reframe"], "reframe")
    held = _effect(["confirm_plain"], ["confirm_reframe"], "reframe")
    dev = _effect(["dev_plain"], ["dev_verify_show"], "verify-show")
    h1 = _effect(["test_flash_plain"], ["test_flash_verifyshow"], "verify-show")
    h1b = _effect(["test_qwen_plain"], ["test_qwen_verifyshow"], "verify-show", model="qwen-plus")
    h2 = paired(load("test_flash_plain"), "flash", ("plain", "C2"), ("plain", "C4"), 1)
    h2q = paired(load("test_qwen_plain"), "qwen-plus", ("plain", "C2"), ("plain", "C4"), 1)

    def fmt(r, p_name="p"):
        return (f"{r['diff']:+.2f}, " + (f"{p_name}<.001" if r["p"] < .001 else f"{p_name}={r['p']:.3f}".replace("=0.", "=."))) if r else "pending"

    phases = [
        ("1  Study set", "PrimeVul test, 187 pairs", "neutral",
         ["RQ1-RQ3", "4 presentations explored", "best: reframe on C4", f"  {fmt(study)}"], None),
        ("2  Held-out", "192 disjoint pairs", "bad",
         ["replicate reframe", f"  C4 {fmt(held)}", "", ""], FALSE_ASSURANCE),
        ("3  Development", "PrimeVul valid, 237 pairs", "neutral",
         ["verify, verify-show,", "commit, commit-verify", "freeze verify-show", f"  C4 {fmt(dev)}"], None),
        ("4  Test (run once)", "PrimeVul train, 300 pairs", "good",
         [f"H1 deepseek-chat", f"  C4 {fmt(h1)}", "H1b qwen-plus", f"  C4 {fmt(h1b)}",
          "H2 C4$-$C2, plain", f"  chat {fmt(h2)}", f"  qwen {fmt(h2q)}"], "#1B7F3A"),
    ]
    for x, (title, sub, fill, rows, col) in zip(xs, phases):
        box(ax, x, y0, W, h, fill, title)
        ax.text(x + W / 2, y0 + h - 0.27, sub, ha="center", va="top", fontsize=6.3, color=MUTED, style="italic")
        lines(ax, x + 0.09, y0 + h - 0.5, rows, dy=0.17, fontsize=6.6)
        if col == FALSE_ASSURANCE:
            ax.text(x + 0.09, y0 + h - 0.5 - 3 * 0.17, "not replicated", fontsize=6.6, weight="bold", color=col, va="top")
    for i in range(3):
        arrow(ax, (xs[i] + W, y0 + h / 2), (xs[i + 1], y0 + h / 2))
    ax.text(xs[1] + W + gap / 2, y0 + h / 2 - 0.08, "stricter\nprotocol", ha="center", va="top", fontsize=5.6,
            color=MUTED)
    ax.text(xs[2] + W + gap / 2, y0 + h / 2 - 0.08, "register\nH1, H1b,\nH2", ha="center", va="top", fontsize=5.6,
            color="#5B2C83", weight="bold")
    fig.savefig(os.path.join(out, "protocol.pdf"))
    plt.close(fig)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="paper/figures")
    ap.add_argument("--preview", help="also write PNG copies to this directory")
    args = ap.parse_args(argv)
    style()
    targets = [args.out] + ([args.preview] if args.preview else [])
    for out in targets:
        os.makedirs(out, exist_ok=True)
        saved = plt.Figure.savefig
        if out != args.out:
            plt.Figure.savefig = lambda self, path, **kw: saved(self, path.replace(".pdf", ".png"), dpi=200, **kw)
        try:
            overview(out)
            verify_show(out)
            protocol(out)
        finally:
            plt.Figure.savefig = saved
    print(f"diagrams written to {args.out}")


if __name__ == "__main__":
    main()
