"""Persisted R2 evidence must not share a result identity with the older fusion output."""
from patchtrace.enrichment.identity import domain_id
from patchtrace.unified import compute, keys
from patchtrace.unified.contracts import ResultKeyInputs
from patchtrace.unified.ladder.residual import pass_table, table_digest
from patchtrace.unified.registry import REGISTRY


def test_revised_fusion_output_cannot_reuse_a_ude1_result_cache():
    # Reconstruct the exact pre-R2 pass-table payload: the wire engine stays ude/1,
    # while new evidence policy must invalidate its cached configurations.
    previous_passes = domain_id('unified-pass-tables', 1,
                               {'registry': REGISTRY.pass_table_digest(),
                                'ladder': table_digest(pass_table())})
    previous = keys.config_digest(pass_table_digest=previous_passes,
                                  registry_digest=REGISTRY.digest(),
                                  channel_versions=dict(REGISTRY.channel_versions),
                                  proof_versions=dict(REGISTRY.proof_versions),
                                  limits_digest=keys.limits_digest())
    current = compute.compute_config_digest()
    old = ResultKeyInputs(older_sha256='4' * 64, newer_sha256='5' * 64,
                          ghidriff_raw_sha256='6' * 64, ir_older_digest='7' * 64,
                          ir_newer_digest='8' * 64, sources=(), manual_digest='9' * 64,
                          config_digest=previous)
    new = old.model_copy(update={'config_digest': current})
    assert keys.result_key(old) != keys.result_key(new)
    assert keys.changed_inputs(old, new) == ('config_digest',)
    assert old.ir_older_digest == new.ir_older_digest
    assert old.ir_newer_digest == new.ir_newer_digest


def test_future_match_policy_revision_changes_result_config_only(monkeypatch):
    previous = compute.compute_config_digest()
    before_ingest = keys.ingest_limits_digest()
    monkeypatch.setattr(compute, 'MATCH_POLICY_VERSION', 'matching/future')
    assert compute.compute_config_digest() != previous
    assert keys.ingest_limits_digest() == before_ingest
    assert keys.ENGINE_VERSION == 'ude/1'
