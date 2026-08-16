from poirot.image4 import is_image4, parse_image4_payload


def test_is_image4_detection():
    im4p_stub = b"\x30\x84\x00\x00\x16\x04IM4P\x16\x04krnl\x16\x04test"
    assert is_image4(im4p_stub) is True
    assert is_image4(b"\x7fELF\x02\x01\x01") is False


def test_parse_image4_payload_extracts_tag():
    data = b"\x30\x84\x00\x00\x16\x04IM4P\x16\x04krnl\x16\x04desc\x04\x04ABCD"
    meta, payload = parse_image4_payload(data)
    assert meta["is_image4"] is True
    assert meta["tag"] == "krnl"
