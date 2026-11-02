# Independent CI fixture repair review

Reviewed clean `2f69f083482a927454a48c31ec19fadad09f2fa4` against `178fbeabeb535e874b0212a1ba4cec7f851f50e2`. No blocking finding. The diff changes only six test files and two QA artifacts; production quarantine, pinned version and workflow gates are untouched.

Positive synthetic0.9.0 fixtures preserve their original behavior assertions. Additional0.9.1 controls cover actual probe quarantine, parser refusal despite a fake supported probe, and reconciliation/calibration abstention while retaining source ownership. The desktop exception assertion remains specific and retains resource-close verification.

Fresh independent validation:127passed in21.90s across changed test files, plus36passed in0.69s in the disjoint orientation policy selection. Ruff/whitespace and changed-path inventory passed.

This is synthetic helper-review evidence, not native compatibility, calibrated-model acceptance, GitHub APPROVE or Windows/full-suite acceptance.
