"""Swift and C++ symbol demangling.

Uses platform runtime __cxa_demangle for C++ and swift-demangle subprocess
(when available) with in-memory caching and graceful fallback.
"""
from __future__ import annotations

import ctypes
import functools
import shutil
import subprocess

# C++ demangling via ctypes (__cxa_demangle)
_cxa_demangle = None
_free = None

try:
    for libname in ("libc++.so.1", "libstdc++.so.6", "libc++.dylib", "msvcp140.dll"):
        try:
            lib = ctypes.CDLL(libname)
            if hasattr(lib, "__cxa_demangle"):
                _cxa_demangle = lib.__cxa_demangle
                _cxa_demangle.argtypes = [
                    ctypes.c_char_p,
                    ctypes.c_char_p,
                    ctypes.POINTER(ctypes.c_size_t),
                    ctypes.POINTER(ctypes.c_int),
                ]
                _cxa_demangle.restype = ctypes.c_void_p
                break
        except OSError:
            pass

    libc = ctypes.CDLL(None)
    if hasattr(libc, "free"):
        _free = libc.free
        _free.argtypes = [ctypes.c_void_p]
        _free.restype = None
except Exception:
    pass

_HAS_SWIFT_DEMANGLE = shutil.which("swift-demangle") is not None


def _demangle_cpp(name: str) -> str | None:
    """Demangle an Itanium C++ symbol name (_Z...)."""
    if not _cxa_demangle:
        return None
    candidate = name.lstrip("_")
    if not candidate.startswith("Z"):
        return None
    candidate = "_" + candidate

    status = ctypes.c_int()
    res_ptr = _cxa_demangle(candidate.encode("utf-8"), None, None, ctypes.byref(status))
    if status.value == 0 and res_ptr:
        try:
            result = ctypes.cast(res_ptr, ctypes.c_char_p).value
            if result:
                return result.decode("utf-8", errors="replace")
        finally:
            if _free and res_ptr:
                try:
                    _free(res_ptr)
                except Exception:
                    pass
    return None


def _demangle_swift(name: str) -> str | None:
    """Demangle a Swift symbol ($s..., _$s..., _T...) via swift-demangle if installed."""
    if not _HAS_SWIFT_DEMANGLE:
        return None
    if not any(name.startswith(p) for p in ("$s", "_$s", "$S", "_$S", "_T")):
        return None
    try:
        res = subprocess.check_output(
            ["swift-demangle", "--compact", name],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).strip()
        if res and res != name:
            return res
    except Exception:
        pass
    return None


@functools.lru_cache(maxsize=4096)
def demangle_symbol(name: str) -> str:
    """Demangle a C++ or Swift symbol. Returns the original name if demangling fails."""
    if not name or len(name) < 3:
        return name

    # Try Swift first if matching prefix
    if name.startswith(("$s", "_$s", "$S", "_$S", "_T")):
        swift_res = _demangle_swift(name)
        if swift_res:
            return swift_res

    # Try C++
    if "_Z" in name:
        cpp_res = _demangle_cpp(name)
        if cpp_res:
            return cpp_res

    return name
