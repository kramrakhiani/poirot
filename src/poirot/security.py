from __future__ import annotations

from .models import SecuritySignal

SIGNAL_RULES: dict[str, tuple[str, tuple[str, ...]]] = {
    "authentication": ("Authentication-related identifier or API reference.", ("auth", "login", "authenticate", "biometric", "passcode", "localauthentication")),
    "authorization": ("Authorization or entitlement-related identifier or API reference.", ("entitlement", "authorization", "permission", "accesscontrol")),
    "cryptography": ("Cryptographic identifier or API reference.", ("crypt", "encrypt", "decrypt", "seckey", "commoncrypto", "openssl", "cccrypt", "securetransport")),
    "keychain": ("Credential-store identifier or API reference.", ("keychain", "ksecclass", "seckeychain", "secitem")),
    "networking": ("Network-related identifier or API reference.", ("nsurlsession", "cfnetwork", "urlsession", "http://", "https://", "network.framework")),
    "filesystem": ("Filesystem-related identifier or API reference.", ("nsfilemanager", "filemanager", "openat", "unlink", "chmod", "nsfileprotection")),
    "process_execution": ("Process-launch identifier or API reference.", ("nstask", "processbuilder", "posix_spawn", "system(", "execve")),
    "webview": ("Embedded-web-content identifier or API reference.", ("wkwebview", "uiwebview", "webkit")),
    "ipc_xpc": ("Inter-process communication or XPC reference.", ("nsxpcconnection", "xpc_connection", "xpc_pipe", "cfmessageport", "nsdistributednotification", "mach_msg")),
    "code_signing": ("Code-signing or integrity-checking reference.", ("seccodecheck", "secstaticcode", "codesign", "csops", "amfi", "provisioning")),
    "sandbox": ("Sandbox or confinement-related reference.", ("sandbox_init", "sandbox_extension", "app-sandbox", "container", "sandboxd")),
    "dynamic_loading": ("Dynamic library loading or runtime manipulation reference.", ("dlopen", "dlsym", "nsbundle", "loadandreturnerror", "cfbundleload")),
    "objc_runtime": ("Objective-C runtime manipulation reference (swizzling, class injection).", ("objc_msgsend", "class_addmethod", "method_exchangeimplementations", "method_setimplementation", "class_replacemethod", "object_setclass")),
}


def derive_security_signals(*sources: list[str]) -> list[SecuritySignal]:
    corpus = sorted({item for source in sources for item in source if item})
    signals: list[SecuritySignal] = []
    for category, (rationale, terms) in SIGNAL_RULES.items():
        evidence = [item for item in corpus if any(term in item.casefold() for term in terms)][:5]
        if evidence:
            signals.append(SecuritySignal(category=category, evidence=evidence, rationale=rationale))
    return signals
