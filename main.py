import argparse

from constants import TYPE_A
from resolver import resolve

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
