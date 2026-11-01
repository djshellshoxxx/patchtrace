# Independent main port — November 1

The calibration tools on main6579ed83211b7ff2039e3152728ac1cddc3e93d6 are byte-identical to the original helper base241f445. Only the reviewed preregistration source/tests/spec/index and its own QA records were ported; unrelated parent stack documentation was not imported. Appended QA/todo conflicts retain main export evidence and only the new preregistration records.

Independent author review approved source42a3d5dee13ac4ff87436a66f787c6b3b5e093ad after102 bounded tests. Coordinator independently ran `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python -m pytest -q tests/test_train_prereg_selection.py tests/test_prereg_tools.py tests/test_prereg_constants.py tests/test_export_destination_guard.py`:112passed in2.63s. Whole-treeRuff and diff checks passed. Full cross-OS gates remain pending for the published independent head. No real corpus or locked evaluation was read/consumed.
