import pytest
from pydantic import ValidationError

from patchtrace.models import Artifact, ComparisonProject, EvidenceReference, FunctionMatch


def artifact(side='older', **changes):
    data = dict(side=side, name='input.dll', sha256='a' * 64, size=1024, relative_path='artifacts/a.bin')
    data.update(changes)
    return Artifact(**data)


@pytest.mark.parametrize('path', ['../input', '/tmp/input', 'C:\\input', 'a/../../b', '\\\\host\\share'])
def test_path_cannot_escape_project(path):
    with pytest.raises(ValidationError):
        artifact(relative_path=path)


def test_schema_version_and_extra_fields_rejected():
    with pytest.raises(ValidationError):
        artifact(schema_version=2)
    with pytest.raises(ValidationError):
        artifact(credential='secret')


def test_duplicate_artifact_identity_rejected():
    with pytest.raises(ValidationError):
        ComparisonProject(name='x', artifacts=[artifact(id='same'), artifact('newer', id='same')])


def test_empty_match_and_reversed_evidence_rejected():
    with pytest.raises(ValidationError):
        FunctionMatch(run_id='x', category='ambiguous')
    with pytest.raises(ValidationError):
        EvidenceReference(artifact_id='a', run_id='r', function_id='f', side='older',
                          start_line=2, end_line=1, text='x')
