from model import header_to_bytes, DNSHeader


def test_header_conversion():
    bytez = header_to_bytes(
        DNSHeader(
            id=0x1314,
            flags=0,
            num_questions=1,
            num_additionals=0,
            num_authorities=0,
            num_answers=0
        )
    )
    expected_result = b'\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    assert bytez == expected_result
