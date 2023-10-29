from parsers import encode_dns_name


def test_domain_encoding():
    actual = encode_dns_name("google.com")
    expected = b'\x06google\x03com\x00'
    assert actual == expected
