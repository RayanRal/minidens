import struct
from io import BytesIO

from constants import COMPRESSION_MARKER, COMPRESSED_POINTER, TYPE_NS, TYPE_A
from model import DNSHeader, DNSQuestion, DNSRecord, DNSPacket


def parse_header(reader: BytesIO) -> DNSHeader:
    items = struct.unpack("!HHHHHH", reader.read(12))
    # see "a note on BytesIO" for an explanation of `reader` here
    return DNSHeader(*items)


def parse_question(reader: BytesIO) -> DNSQuestion:
    name = decode_name(reader)
    data = reader.read(4)
    type_, clazz = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, clazz)


def parse_record(reader: BytesIO) -> DNSRecord:
    name = decode_name(reader)
    # the type, class, TTL, and data length together are 10 bytes (2 + 2 + 4 + 2 = 10)
    data = reader.read(10)
    # HHIH means 2-byte int, 2-byte-int, 4-byte int, 2-byte int
    type_, clazz, ttl, data_len = struct.unpack("!HHIH", data)
    if type_ == TYPE_NS:
        data = decode_name(reader)
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_len))
    else:
        data = reader.read(data_len)
    return DNSRecord(name, type_, clazz, ttl, data)


def parse_dns_packet(data: bytes) -> DNSPacket:
    bytes_reader = BytesIO(data)
    header = parse_header(bytes_reader)
    questions = [parse_question(bytes_reader) for _ in range(header.num_questions)]
    answers = [parse_record(bytes_reader) for _ in range(header.num_answers)]
    authorities = [parse_record(bytes_reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(bytes_reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)


def decode_name(reader: BytesIO) -> bytes:
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & COMPRESSION_MARKER:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def encode_dns_name(domain_name: str) -> bytes:
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def decode_compressed_name(length, reader: BytesIO) -> bytes:
    pointer_bytes = bytes([length & COMPRESSED_POINTER]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


def ip_to_string(ip: bytes) -> str:
    return ".".join([str(x) for x in ip])
