from pathlib import Path
from zdh.cli import scan_path

def test_vulnerable_fixture():
    fs=scan_path(Path(__file__).parent/'fixtures'/'vulnerable.php')
    kinds={x.kind for x in fs}
    assert 'xss' in kinds
    assert 'command_injection' in kinds
    assert 'file_inclusion' in kinds

def test_safe_fixture_has_no_high_xss():
    fs=scan_path(Path(__file__).parent/'fixtures'/'safe.php')
    assert not any(x.kind=='xss' and x.confidence>=80 for x in fs)
