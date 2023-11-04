import dataclasses
import struct
from dataclasses import dataclass
from typing import List


@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    clazz: int


@dataclass
class DNSRecord:
    name: bytes
    type_: int
    clazz: int
    ttl: int
    data: bytes


@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]


# TODO: this doesn't work yet
def packet_to_bytes(packet: DNSPacket) -> bytes:
    fields = dataclasses.astuple(packet)
    return struct.pack("!HHHHHH", *fields)


# big endian encoding
def header_to_bytes(header: DNSHeader) -> bytes:
    fields = dataclasses.astuple(header)
    return struct.pack("!HHHHHH", *fields)


def question_to_bytes(question: DNSQuestion) -> bytes:
    return question.name + struct.pack("!HH", question.type_, question.clazz)
