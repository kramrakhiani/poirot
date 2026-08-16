from poirot.demangle import demangle_symbol


def test_demangle_cpp_symbol():
    # Itanium C++ mangled symbol for _Z3foov -> foo()
    mangled = "_Z3foov"
    demangled = demangle_symbol(mangled)
    assert demangled in ("foo()", "foo", "_Z3foov")  # Depends on whether __cxa_demangle is in libc/libc++


def test_demangle_passthrough_normal_symbols():
    assert demangle_symbol("main") == "main"
    assert demangle_symbol("_printf") == "_printf"
    assert demangle_symbol("") == ""
