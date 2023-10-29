import unittest

from parsers import encode_dns_name


class EncoderTestCase(unittest.TestCase):
    def test_domain_encoding(self):
        actual = encode_dns_name("google.com")
        expected = b'\x06google\x03com\x00'
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
