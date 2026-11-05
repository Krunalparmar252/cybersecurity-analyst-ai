"""
Benchmark Matching Engine.
Matches candidate findings against ground truth labels with +-3 line tolerance,
one-to-one label matching, and separation of true positives, false positives,
false negatives, and unlabeled findings.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple


def normalize_path(path: str) -> str:
    """Normalize file path to unix style relative path."""
    return path.replace("\\", "/").strip("./")


# Class family equivalence for security findings
CLASS_FAMILIES = {
    "sql injection": {"sql injection", "sqli", "cwe-89"},
    "cross-site scripting": {"cross-site scripting", "xss", "cwe-79"},
    "command injection": {"command injection", "cmdinj", "os command injection", "cwe-78"},
    "path traversal": {"path traversal", "pathtrav", "zip slip", "cwe-22", "directory traversal"},
    "unsafe deserialization": {"unsafe deserialization", "deserialization", "deser", "cwe-502", "insecure deserialization"},
    "hardcoded secrets": {"hardcoded secrets", "hardcoded secret", "secret", "cwe-798"},
    "server-side request forgery": {"server-side request forgery", "ssrf", "cwe-918"},
    "open redirect": {"open redirect", "unvalidated redirect", "unvalidated redirects and forwards", "cwe-601"},
    "insecure cryptography": {"insecure cryptography", "crypto", "weak hash", "weak cipher", "cwe-328", "cwe-327", "cwe-338"},
    "broken authentication": {"broken authentication", "insecure authentication", "auth", "cwe-287", "cwe-328", "cwe-614"},
    "xml external entity": {"xml external entity", "xxe", "cwe-611"},
    "server-side template injection": {"server-side template injection", "ssti", "cwe-1336"},
    "security misconfiguration": {"security misconfiguration", "config", "cwe-489", "cwe-614"},
}


def classes_match(class1: str, class2: str, cwe1: Optional[str] = None, cwe2: Optional[str] = None) -> bool:
    """Check if two vulnerability classes or CWEs match."""
    c1 = (class1 or "").strip().lower()
    c2 = (class2 or "").strip().lower()
    if c1 == c2 and c1 != "":
        return True

    cw1 = (cwe1 or "").strip().lower()
    cw2 = (cwe2 or "").strip().lower()
    if cw1 and cw2 and cw1 == cw2:
        return True

    for fam_name, members in CLASS_FAMILIES.items():
        in_1 = c1 in members or cw1 in members
        in_2 = c2 in members or cw2 in members
        if in_1 and in_2:
            return True

    return False


@dataclass
class MatchResult:
    true_positives: List[Dict[str, Any]]
    false_positives: List[Dict[str, Any]]
    false_negatives: List[Dict[str, Any]]
    unlabeled: List[Dict[str, Any]]
    total_labels: int
    total_findings: int

    @property
    def precision(self) -> float:
        tp = len(self.true_positives)
        fp = len(self.false_positives)
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        tp = len(self.true_positives)
        fn = len(self.false_negatives)
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        return (2 * p * r) / (p + r) if (p + r) > 0 else 0.0


def match_findings_to_labels(
    findings: List[Any],
    labels: List[Dict[str, Any]],
    tolerance: int = 3,
) -> MatchResult:
    """
    Evaluates findings against ground truth labels.
    - True Positive: same file, matching class/CWE family, line within +-tolerance.
    - One-to-one matching: each label can match at most once.
    - False Negative: an in-scope label not matched by any finding.
    - False Positive: finding within +-tolerance of a label with wrong class, or duplicate match on same label.
    - Unlabeled: findings on files or lines with no label.
    """
    labels_by_file: Dict[str, List[Dict[str, Any]]] = {}
    for l in labels:
        f_norm = normalize_path(l["file"])
        labels_by_file.setdefault(f_norm, []).append(l)

    matched_label_ids: set[str] = set()
    true_positives: List[Dict[str, Any]] = []
    false_positives: List[Dict[str, Any]] = []
    unlabeled: List[Dict[str, Any]] = []

    for f in findings:
        f_file = normalize_path(getattr(f, "file", f.get("file", "") if isinstance(f, dict) else ""))
        f_line = getattr(f, "line", f.get("line", 0) if isinstance(f, dict) else 0)
        f_class = getattr(f, "vuln_class", getattr(f, "rule_class", getattr(f, "vulnerability_class", f.get("class", "") if isinstance(f, dict) else "")))
        f_cwe = getattr(f, "cwe", f.get("cwe", "") if isinstance(f, dict) else "")
        f_rule = getattr(f, "rule_id", f.get("rule_id", "") if isinstance(f, dict) else "")
        f_snippet = getattr(f, "snippet", f.get("snippet", "") if isinstance(f, dict) else "")
        f_dataflow = getattr(f, "dataflow", f.get("dataflow", []) if isinstance(f, dict) else [])

        f_dict = {
            "file": f_file,
            "line": f_line,
            "rule_id": f_rule,
            "class": f_class,
            "cwe": f_cwe,
            "snippet": f_snippet,
            "dataflow": f_dataflow,
        }

        # Check if file has any labels
        candidates = labels_by_file.get(f_file, [])
        if not candidates:
            # File has no labels -> unlabeled finding
            unlabeled.append(f_dict)
            continue

        # Look for a label within +-tolerance
        close_labels = [l for l in candidates if abs(l["line"] - f_line) <= tolerance]
        if not close_labels:
            # Finding is in a labeled file, but not at a labeled line range
            unlabeled.append(f_dict)
            continue

        # Check if any close label matches class
        matched_label = None
        for l in close_labels:
            if classes_match(f_class, l["class"], f_cwe, l.get("cwe")):
                if l["id"] not in matched_label_ids:
                    matched_label = l
                    break

        if matched_label:
            matched_label_ids.add(matched_label["id"])
            true_positives.append({
                "label": matched_label,
                "finding": f_dict,
            })
        else:
            # Close to a labeled line, but class mismatch or duplicate hit
            false_positives.append(f_dict)

    # Remaining unmatched labels are false negatives
    false_negatives = [l for l in labels if l["id"] not in matched_label_ids]

    return MatchResult(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        unlabeled=unlabeled,
        total_labels=len(labels),
        total_findings=len(findings),
    )
