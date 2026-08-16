from poirot.diff import diff_binaries
from poirot.models import BinaryAnalysis, Function


def test_diff_binaries_with_filter_and_min_score():
    old = BinaryAnalysis(
        path="old.bin",
        format="Mach-O",
        architecture="arm64",
        entry_point=0x1000,
        functions=[
            Function(name="auth_login", size=100),
            Function(name="render_ui", size=200),
            Function(name="crypto_sign", size=300),
        ],
    )
    new = BinaryAnalysis(
        path="new.bin",
        format="Mach-O",
        architecture="arm64",
        entry_point=0x1000,
        functions=[
            Function(name="auth_login", size=180),  # size delta 80 -> score ~48
            Function(name="render_ui", size=210),   # size delta 10 -> score ~3
            Function(name="crypto_sign", size=500), # size delta 200 -> score ~40
        ],
    )

    # 1. Test filtering by pattern
    filtered_res = diff_binaries(old, new, filter_pattern="auth|login")
    assert len(filtered_res["function_changes"]["modified"]) == 1
    assert filtered_res["function_changes"]["modified"][0]["function"] == "auth_login"

    # 2. Test filtering by minimum score (auth_login score is 27, crypto_sign is 24, render_ui is 3)
    score_res = diff_binaries(old, new, min_score=25)
    assert len(score_res["function_changes"]["modified"]) == 1
    assert score_res["function_changes"]["modified"][0]["function"] == "auth_login"
