import argparse
import random
import socket
from collections import namedtuple
from functools import lru_cache
from typing import Optional

from constants import CLASS_IN, DNS_PORT, TYPE_A, TYPE_NS, ROOT_NAMESERVER, TYPE_CNAME
from parsers import encode_dns_name, parse_dns_packet
from model import DNSHeader, DNSQuestion, header_to_bytes, question_to_bytes, DNSPacket

random.seed(42)


def build_query(domain_name: str, record_type: int) -> bytes:
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    RECURSION_DESIRED = 1 << 8  # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, clazz=CLASS_IN)
    query = header_to_bytes(header) + question_to_bytes(question)
    return query


@lru_cache
def send_query(ns_ip_address: str, domain_name: str, record_type: int) -> DNSPacket:
    query = build_query(domain_name, record_type)
    # socket.AF_INET means we're connecting to the internet (as opposed to a Unix domain socket `AF_UNIX` for example)
    socket_family = socket.AF_INET
    socket_type = socket.SOCK_DGRAM  # UDP
    sock = socket.socket(socket_family, socket_type)
    sock.sendto(query, (ns_ip_address, DNS_PORT))
    response, _ = sock.recvfrom(1024)
    print(f"Got {response=}")
    return parse_dns_packet(response)


def get_answer(packet: DNSPacket) -> Optional[str]:
    for x in packet.answers:
        if x.type_ == TYPE_A:
            # it's actually a str already, as we cut corners and stored parsed data in DNSPacket
            return str(x.data)


# This method doesn't work yet
def get_cname_alias(packet: DNSPacket) -> Optional[str]:
    for x in packet.authorities:
        if x.type_ == TYPE_A:
            return str(x.data)


def get_nameserver_ip(packet: DNSPacket) -> Optional[bytes]:
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data


def get_nameserver(packet: DNSPacket) -> Optional[str]:
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode('utf-8')


@lru_cache
def resolve(domain_name: str, record_type: int) -> str:
    nameserver = ROOT_NAMESERVER
    domain = domain_name
    while True:
        print(f"Querying {nameserver} for {domain}")
        response = send_query(nameserver, domain, record_type)
        if ip := get_answer(response):
            return ip
        # elif domain_alias := get_cname_alias(response):
        #     domain = domain_alias
        elif ns_ip := get_nameserver_ip(response):
            nameserver = ns_ip
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            raise Exception(f"Can't resolve {domain_name}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Resolve domain name')
    parser.add_argument('name', type=str,
                        help='domain name to be resolved')
    parser.add_argument('-type', type=int, required=False,
                        default=TYPE_A, choices=[1, 5],
                        help='Type of domain (A, CNAME) to resolve')

    args = parser.parse_args()
    domain_name = args.name
    domain_type = args.type
    print(f"Resolving {domain_name=}")
    result = resolve(domain_name, domain_type)
    print(f"Resolved to {result=}")
