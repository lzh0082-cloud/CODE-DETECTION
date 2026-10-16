# Quick check (about 15-20 minutes)

For each row, read the notes and the excerpt of the model's answer, then write Y or N in `rejects_false_note`:

* **Y**: the answer says that at least one note is wrong, inaccurate, a false positive, or does not match the code.
* **N**: the answer accepts the notes, ignores them, or only says they are incomplete/irrelevant.

Write `?` if you cannot tell and add a remark in `comment`. Label on your own: do not open sheet_claude.csv,
sheet_deepseek.csv, labels_claude.jsonl or key.csv before you finish. The full answer of every item is in
sheet.csv (same item number) if you need more context.

When done, run from the project folder:

    python -m sgv.annotate score annotation/quick_check_20.csv annotation/sheet_claude.csv
    python -m sgv.annotate score annotation/quick_check_20.csv annotation/sheet_deepseek.csv
