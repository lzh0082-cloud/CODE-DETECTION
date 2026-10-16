# Annotation guide: does the model scrutinise the static-analysis notes?

Each row shows the static-analysis notes given to the model (some notes are deliberately FALSE) and the
model's answer. Read the answer and fill three columns with Y or N. Do not look at key.csv.

* **checks_notes**: the answer explicitly compares at least one note with the code (e.g. "line 8 is the
  loop condition, so the index is guarded").
* **rejects_false_note**: the answer says that a note is wrong, inaccurate or does not match the code.
* **verdict_relies_on_note**: the final verdict is justified (at least partly) by a note, taken at face value.

Label the three columns independently of whether the final verdict is right. When unsure, write `?` and add a
remark in `comment`.
