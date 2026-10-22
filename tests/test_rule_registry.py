"""Task 4: rules.yaml matches the code; new rules fire/skip; secrets redacted."""
import re
from pathlib import Path

import yaml

from analyst.detection.engine import run_detection
from analyst.ingestion.manifest import ingest_repo

DET = Path(__file__).resolve().parent.parent / "analyst" / "detection"
RAW = {
    "aws_id": "AKIAIOSFODNN7EXAMPLQ",
    "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "gh": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "blob": "Zx9$kQ2mPz7LwR4tYb8NcV3hJd6Fg1Sa",
}


def _implemented_ids():
    ids = set()
    for name in ("engine.py", "rules_extra.py"):
        src = (DET / name).read_text()
        ids |= set(re.findall(r'(?:rule_id=|_mk\(|report\()"([A-Z]+-\d{3})"', src))
    return ids


def test_rules_yaml_matches_implemented_rules():
    cat = yaml.safe_load((DET / "rules.yaml").read_text())
    listed = {r["id"] for r in cat["rules"]}
    assert listed == _implemented_ids()
    assert not listed & set(cat["not_implemented"])


def _scan(tmp_path, files):
    for n, body in files.items():
        (tmp_path / n).write_text(body)
    return run_detection(ingest_repo(str(tmp_path)))


def test_new_rules_fire_and_safe_variants_do_not(tmp_path):
    py = (
        "import hashlib\n"
        "def q(c, n):\n"
        "    c.execute(\"SELECT * FROM t WHERE n = '%s'\" % n)\n"          # 3 SQLI-002
        "    c.execute(\"SELECT * FROM t WHERE n = '{}'\".format(n))\n"    # 4 SQLI-002
        "    c.execute(\"SELECT * FROM t WHERE n = %s\", (n,))\n"          # 5 safe
        "def login(password, stored):\n"
        "    if password == stored:\n"                                     # 7 AUTH-001
        "        return hashlib.md5(password.encode()).hexdigest()\n"      # 8 AUTH-002
        "def ok(password, h):\n"
        "    return check_password_hash(h, password)\n"                    # safe
        "T = '<p>{{ name|safe }}</p>'\n"                                   # 11 XSS-003
    )
    js = (
        "const A = ({html}) => <div dangerouslySetInnerHTML={{__html: html}} />;\n"
        "const B = () => <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(x)}} />;\n"
        "eval(req.body.code);\n"
        "eval('1+1');\n"
    )
    got = {(f.file, f.line, f.rule_id) for f in _scan(tmp_path, {"a.py": py, "b.js": js})}
    for want in [("a.py", 3, "SQLI-002"), ("a.py", 4, "SQLI-002"), ("a.py", 7, "AUTH-001"),
                 ("a.py", 8, "AUTH-002"), ("a.py", 11, "XSS-003"), ("b.js", 1, "XSS-001"),
                 ("b.js", 3, "DESER-002")]:
        assert want in got, want
    for bad in [("a.py", 5), ("a.py", 10), ("b.js", 2), ("b.js", 4)]:
        assert not any(g[:2] == bad for g in got), bad
    assert ("a.py", 3, "SQLI-001") not in got  # superseded, reported once


def test_secret_rules_fire_and_never_leak_raw_values(tmp_path):
    body = (
        f'AK = "{RAW["aws_id"]}"\n'
        f'aws_secret_access_key = "{RAW["aws_secret"]}"\n'
        f'GH = "{RAW["gh"]}"\n'
        f'blob = "{RAW["blob"]}"\n'
        "# -----BEGIN RSA PRIVATE KEY-----\n"
        'name = "changeme-changeme-changeme"\n'
    )
    found = _scan(tmp_path, {"s.py": body})
    by_line = {f.line: f.rule_id for f in found}
    assert by_line == {1: "SECRET-001", 2: "SECRET-002", 3: "SECRET-003",
                       4: "SECRET-006", 5: "SECRET-007"}
    blob = "\n".join(f.snippet + f.to_dict()["snippet"] for f in found)
    for raw in RAW.values():
        assert raw not in blob
