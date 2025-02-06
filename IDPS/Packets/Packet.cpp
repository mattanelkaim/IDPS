#include "Packet.h"
#include <iostream>
#include <stdexcept> // std::runtime_error


Packet::Packet(const std::span<const uint8_t> rawData) :
    ethernetHeader(new EthernetHeader(rawData.subspan(0, sizeof(EthernetHeader)))),
	timestamp(*reinterpret_cast<const uint64_t*>(rawData.data()))
{
	std::cout << "\033[31mTimestamp:\033[0m " << timestamp << '\n';
    std::cout << "\n\033[41mEthernet:\033[0m\n" << *ethernetHeader << '\n';
    size_t offset = sizeof(EthernetHeader);

    // Parse NETWORK layer
    if (ethernetHeader->etherType == IPV4)
    {
        this->networkHeader = new IPv4Header(rawData.subspan(offset, sizeof(IPv4Header)));
        offset += sizeof(IPv4Header);
        this->transportProtocol = static_cast<IPv4Header*>(networkHeader)->protocol;
        std::cout << "\033[42mIP:\033[0m\n" << *static_cast<IPv4Header*>(networkHeader) << '\n';
    }
    else if (ethernetHeader->etherType == ARP)
    {
        this->networkHeader = new ArpHeader(rawData.subspan(offset, sizeof(ArpHeader)));
        this->transportProtocol = NONE;
        std::cout << "\033[42mIP:\033[0m\n" << *static_cast<ArpHeader*>(networkHeader) << '\n';
        return; // No transport layer!
    }
    else // Probably IPv6
    {
        throw std::runtime_error("Unsupported network protocol");
    }

    // Parse TRANSPORT layer
    if (this->transportProtocol == TCP)
    {
        this->transportHeader = new TCPHeader(rawData.subspan(offset, sizeof(TCPHeader)));
        offset += sizeof(TCPHeader);
        std::cout << "\033[43mTCP:\033[0m\n" << *static_cast<TCPHeader*>(transportHeader) << '\n';
    }
    else if (this->transportProtocol == UDP)
    {
        this->transportHeader = new UDPHeader(rawData.subspan(offset, sizeof(UDPHeader)));
        offset += sizeof(UDPHeader);
        std::cout << "\033[43mUDP:\033[0m\n" << *static_cast<UDPHeader*>(transportHeader) << '\n';
    }
    else
    {
        throw std::runtime_error("Unsupported transport protocol");
    }

    // Parse APPLICATION layer
    if (this->transportHeader->srcPort == DNSHeader::DEFAULT_PORT ||
        this->transportHeader->dstPort == DNSHeader::DEFAULT_PORT)
    {
        this->applicationData = new DNSMessage(rawData.subspan(offset));
        std::cout << "\033[44mDNS (header):\033[0m\n" << (*static_cast<DNSMessage*>(applicationData)).header;
    }
}

Packet::~Packet()
{
    delete ethernetHeader;
    delete networkHeader;
    delete transportHeader;
    delete applicationData;
}
