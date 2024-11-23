from scapy.all import *
import re

LOGO = r"""
  /$$$$$$   /$$$$$$  /$$   /$$ /$$   /$$ /$$$$$$$$ /$$$$$$$$ /$$$$$$$              /$$$$$$ /$$$$$$$  /$$$$$$$   /$$$$$$ 
 /$$__  $$ /$$__  $$| $$  | $$| $$$ | $$|__  $$__/| $$_____/| $$__  $$            |_  $$_/| $$__  $$| $$__  $$ /$$__  $$
| $$  \__/| $$  \ $$| $$  | $$| $$$$| $$   | $$   | $$      | $$  \ $$              | $$  | $$  \ $$| $$  \ $$| $$  \__/
| $$      | $$  | $$| $$  | $$| $$ $$ $$   | $$   | $$$$$   | $$$$$$$/              | $$  | $$  | $$| $$$$$$$/|  $$$$$$ 
| $$      | $$  | $$| $$  | $$| $$  $$$$   | $$   | $$__/   | $$__  $$              | $$  | $$  | $$| $$____/  \____  $$
| $$    $$| $$  | $$| $$  | $$| $$\  $$$   | $$   | $$      | $$  \ $$              | $$  | $$  | $$| $$       /$$  \ $$
|  $$$$$$/|  $$$$$$/|  $$$$$$/| $$ \  $$   | $$   | $$$$$$$$| $$  | $$             /$$$$$$| $$$$$$$/| $$      |  $$$$$$/
 \______/  \______/  \______/ |__/  \__/   |__/   |________/|__/  |__/            |______/|_______/ |__/       \______/ 
""".strip()  # Remove unnecessary newlines

BANNER = f"""\n                                           Welcome to the attacks swiss knife\n\n{LOGO}
\nDISCLAIMER: Use responsibly and ethically.
\n――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――\n"""

HELP = """Supported commands:
- set {target} {ip}
- attack {ddos|arp}
- help
- exit"""

IP_REGEX_PATTERN_STRING: str = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                               r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                               r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                               r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
IP_REGEX_MATCHER: re.Pattern = re.compile(IP_REGEX_PATTERN_STRING)

LOCAL_IP = get_if_addr(conf.iface)


def get_command() -> str:
    user_command = input("\n> ").lower()
    return user_command


def resolve_target(target: str) -> str:
    # Handle edge case
    print(f"Resolving {target}...")
    if target in ("localhost", "127.0.0.1"):
        return LOCAL_IP

    if not IP_REGEX_MATCHER.match(target):
        try:
            # Returns: (family, type, proto, canonname, sockaddr)
            return socket.getaddrinfo(target, None)[0][-1][0]  # Extract IP
        except socket.gaierror:
            print("Invalid target! Specify a valid IP address or a domain")
            return ""
    else:  # Target is already IP
        return target


# Receives a VALID IP address!
def is_local_ip(ip: str) -> bool:
    ip_bytes = ip.split('.')
    return ip_bytes[0] == '10' or ip_bytes[0:1] == ['192.168'] \
        or (ip_bytes[0] == '172' and 16 <= int(ip_bytes[1]) <= 31)


def is_valid_port(port: str) -> bool:
    return 1 <= int(port) <= 65535


def extract_ports(ports: str) -> list[int]:
    # Handle edge case of unspecified
    if ports == '':
        return []

    port_list = []
    for port_range in ports.split(","):
        if "-" in port_range:
            start, end = port_range.split("-")
            if is_valid_port(start) and is_valid_port(end):
                port_list.extend(range(int(start), int(end) + 1))
        elif is_valid_port(port_range):
            port_list.append(int(port_range))

    return port_list
