"""Adapters that feed the KB correlator from KEV, WB1 search, FAB anchors and unified results (K8).

Pure: no Qt, network or sqlite. Each adapter reads plain values and returns the correlator's own ports and records.
Unknown or missing input becomes ``unknown``/``no-snapshot``, never a negative vote; text from other tracks is cleaned
before it reaches a row; every record names its provenance.
"""
