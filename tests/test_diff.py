from poirot.diff import diff_binaries, llm_evidence
from poirot.models import BinaryAnalysis, Function


def test_named_functions_are_matched_deterministically():
    old = BinaryAnalysis("old", "ELF", "x86_64", None, functions=[Function("auth", size=10)])
    new = BinaryAnalysis("new", "ELF", "x86_64", None, functions=[Function("auth", size=30), Function("new_fn", size=2)])
    report = diff_binaries(old, new)
    assert report["function_changes"]["added"] == ["new_fn"]
    assert report["function_changes"]["modified"][0]["function"] == "auth"


def test_llm_evidence_excludes_bulk_binary_content():
    old = BinaryAnalysis("secret-path", "ELF", "x86_64", None, strings=["private-token"], functions=[Function("f", size=1)])
    new = BinaryAnalysis("new", "ELF", "x86_64", None, strings=["another-secret"], functions=[Function("f", size=2)])
    evidence = llm_evidence(diff_binaries(old, new))
    assert "observed_facts" not in evidence
    assert "private-token" not in str(evidence)
