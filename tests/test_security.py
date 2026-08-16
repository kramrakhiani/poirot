from poirot.security import derive_security_signals


def test_security_triage_is_evidence_backed_and_not_a_finding():
    signals = derive_security_signals(["SecKeyCreateRandomKey", "WKWebView", "unrelated"])
    by_category = {signal.category: signal for signal in signals}
    assert by_category["cryptography"].evidence == ["SecKeyCreateRandomKey"]
    assert by_category["webview"].rationale.startswith("Embedded-web-content")


def test_ios_specific_signals_detect_xpc():
    signals = derive_security_signals(["NSXPCConnection", "_xpc_connection_create"])
    by_category = {signal.category: signal for signal in signals}
    assert "ipc_xpc" in by_category
    assert len(by_category["ipc_xpc"].evidence) == 2


def test_ios_specific_signals_detect_code_signing():
    signals = derive_security_signals(["SecCodeCheckValidityWithErrors", "codesign_allocate"])
    by_category = {signal.category: signal for signal in signals}
    assert "code_signing" in by_category


def test_ios_specific_signals_detect_sandbox():
    signals = derive_security_signals(["sandbox_init", "sandbox_extension_consume"])
    by_category = {signal.category: signal for signal in signals}
    assert "sandbox" in by_category


def test_ios_specific_signals_detect_dynamic_loading():
    signals = derive_security_signals(["dlopen", "dlsym"])
    by_category = {signal.category: signal for signal in signals}
    assert "dynamic_loading" in by_category


def test_ios_specific_signals_detect_objc_runtime():
    signals = derive_security_signals(["method_exchangeImplementations", "class_addMethod"])
    by_category = {signal.category: signal for signal in signals}
    assert "objc_runtime" in by_category


def test_no_false_positives_on_unrelated_strings():
    signals = derive_security_signals(["main", "printf", "HelloWorld"])
    assert signals == []
