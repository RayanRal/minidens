import socket

import resolver
from constants import UDP_SERVER_PORT, UDP_SERVER_IP, ROOT_NAMESERVER
from model import packet_to_bytes
from parsers import parse_dns_packet

if __name__ == '__main__':
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSock.bind((UDP_SERVER_IP, UDP_SERVER_PORT))
    print(f"Bound minidens server to {UDP_SERVER_IP}:{UDP_SERVER_PORT}. Waiting for queries...")
    while True:
        data, addr = serverSock.recvfrom(1024)
        packet = parse_dns_packet(data)
        requested_domain = str(packet.questions[0].name)
        requested_type = packet.questions[0].type_
        print(f"From {addr=}, requested domain {requested_domain}, type {requested_type}")
        response = resolver.send_query(ROOT_NAMESERVER, requested_domain, requested_type)
        response_bytes = packet_to_bytes(response)
        serverSock.sendto(response_bytes, addr)
