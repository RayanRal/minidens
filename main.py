import random
import socket

from parsers import encode_dns_name, parse_dns_packet, ip_to_string
from model import DNSHeader, DNSQuestion, header_to_bytes, question_to_bytes

random.seed(42)

# https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
TYPE_A = 1
# https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
CLASS_IN = 1

DNS_PORT = 53
DNS_SERVER = "8.8.8.8"


def build_query(domain_name: str, record_type: int):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    RECURSION_DESIRED = 1 << 8  # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, clazz=CLASS_IN)
    query = header_to_bytes(header) + question_to_bytes(question)
    return query


def lookup_domain(domain_name: str) -> str:
    query = build_query(domain_name, TYPE_A)
    # socket.AF_INET means we're connecting to the internet (as opposed to a Unix domain socket `AF_UNIX` for example)
    socket_family = socket.AF_INET
    socket_type = socket.SOCK_DGRAM  # UDP
    sock = socket.socket(socket_family, socket_type)
    sock.sendto(query, (DNS_SERVER, DNS_PORT))

    response, _ = sock.recvfrom(1024)
    print(f"Got {response=}")

    packet = parse_dns_packet(response)
    print(f"Parsed {packet=}")
    return ip_to_string(packet.answers[0].data)


if __name__ == '__main__':
    domain_name = "www.example.com"
    print(f"Resolving {domain_name=}")
    resolved_ip = lookup_domain(domain_name)
    print(f"Resolved to {resolved_ip}")
