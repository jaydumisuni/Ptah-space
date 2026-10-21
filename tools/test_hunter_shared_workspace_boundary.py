from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DOC=(ROOT/'docs/HUNTER_WHOLE_SYSTEM_CONSUMER_POINTER_20261010.md').read_text(encoding='utf-8')

def test_future_session_can_recover_eco_architecture():
    assert 'Eco-progress/docs/status/HUNTER_COG_PETE_PTAH_ARMOUR_RECOVERY_20261010.md' in DOC
    assert 'Hunter' in DOC
    assert 'Ptah' in DOC
    assert 'PETE' in DOC

def test_pointer_never_grants_runtime_or_owner_freeze():
    assert 'C4' in DOC and 'C5/C6' in DOC
    assert 'no additional runtime authority' in DOC

def test_native_owner_and_authority_boundary():
    assert 'Ptah provides mechanically durable workspace/session/activity/attempt' in DOC
    assert 'never issues Hunter' in DOC
