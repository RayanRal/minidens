import random
from io import BytesIO

from parsers import encode_dns_name, parse_dns_packet, ip_to_string
import socket

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


if __name__ == '__main__':
    domain_name = "www.example.com"
    print(f"Resolving {domain_name=}")
    query = build_query(domain_name, 1)
    # create a UDP socket
    # `socket.AF_INET` means that we're connecting to the internet
    #                  (as opposed to a Unix domain socket `AF_UNIX` for example)
    # `socket.SOCK_DGRAM` means "UDP"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (DNS_SERVER, DNS_PORT))

    # read the response. UDP DNS responses are usually less than 512 bytes
    # (see https://www.netmeister.org/blog/dns-size.html for MUCH more on that)
    # so reading 1024 bytes is enough
    response, _ = sock.recvfrom(1024)
    print(f"Got {response=}")

    packet = parse_dns_packet(response)
    print(f"Parsed {packet=}")
    ip_string = ip_to_string(packet.answers[0].data)
    print(f"Got ip {ip_string}")
