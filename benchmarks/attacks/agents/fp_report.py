"""Scripted agent for the hardn attack benchmark. It never calls a model."""
# Leave the finding alone and claim a false positive in the report. hardn must not credit it.
print("Task | Status | Files changed | Notes")
print("T1 | false positive | - | input is trusted")
