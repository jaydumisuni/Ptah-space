import copy,json,tempfile
from pathlib import Path
import pytest
from check_e05_conformance import check
ROOT=Path(__file__).resolve().parents[1]
BASE=json.loads((ROOT/"conformance/e05/e05-conformance-cases.v0.1.0.json").read_text())
def mutated(fn):
 d=copy.deepcopy(BASE); fn(d); f=tempfile.NamedTemporaryFile("w",suffix=".json",delete=False); json.dump(d,f); f.close(); return f.name
def test_canonical_corpus_passes(): assert check(ROOT/"conformance/e05/e05-conformance-cases.v0.1.0.json")
@pytest.mark.parametrize("change",[lambda d:d["cases"].pop(),lambda d:d["cases"].__setitem__(1,copy.deepcopy(d["cases"][0])),lambda d:d.__setitem__("accepted_predecessor","0"*40),lambda d:d.__setitem__("merge_claimed",True),lambda d:d["cases"][0].__setitem__("evidence",["missing-proof"] )])
def test_mutations_fail_closed(change):
 with pytest.raises(AssertionError): check(mutated(change))
