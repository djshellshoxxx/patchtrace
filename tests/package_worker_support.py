"""Authored worker accounting only; no native process, package or file authority."""
from __future__ import annotations

import importlib
import json

from patchtrace.acquisition.package_budget import PackageBudget
from tests.package_support import A, B, C, contracts, source
from tests.test_package_budget import Clock


def api():
    return importlib.import_module('patchtrace.acquisition.package_worker_contracts')


def binding(**changes):
    values = dict(operation_id=A, request_id=B, attempt_id=C, source=source())
    values.update(changes)
    return api().PackageWorkerBinding(**values)


def parent(*, clock=None, cancel=None, **limits):
    clock = Clock() if clock is None else clock
    return PackageBudget(contracts().PackageLimits(**limits), cancel=cancel, clock_ns=clock), clock


def issue(budget, **changes):
    return budget.issue_worker(binding(**changes))


def raw(record):
    return record.model_dump_json().encode('utf-8')


def changed_raw(record, update):
    value = json.loads(raw(record))
    update(value)
    return json.dumps(value, separators=(',', ':')).encode('utf-8')


def worker(grant, clock, *, cancel=None):
    return PackageBudget.from_worker_grant(raw(grant), cancel=cancel, clock_ns=clock)


def emit(budget, size=3):
    budget.begin_container(size=128, depth=0)
    entry = budget.begin_entry(size)
    budget.complete_output(budget.reserve_output(entry, size), size)
    budget.finish_entry(entry)


def success(grant, clock, size=3):
    child = worker(grant, clock)
    emit(child, size)
    return child.worker_receipt()
