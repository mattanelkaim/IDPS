#include "Packet.h"
#include <iostream>
#include <stdexcept> // std::runtime_error


Packet::Packet(const std::span<const uint8_t> rawData, bool hasTimestamp) :
    timestamp(hasTimestamp ? *reinterpret_cast<const uint64_t*>(rawData.data()) : 0) // Set timestamp based on flag
{
    if (hasTimestamp)
        std::cout << "\033[48;5;57mTimestamp:\033[0m " << timestamp << '\n';

    // An initial offset depending on timestamp
    size_t offset = hasTimestamp ? sizeof(timestamp) : 0;

    // Try to parse link layer as loopback
    const LoopbackHeader tempHeader(rawData.subspan(offset, sizeof(LoopbackHeader)));

    // Try to parse the link layer
    if (tempHeader.loopbackType != NULL_IPV4) [[likely]]
    {
        this->linkHeader = new EthernetHeader(rawData.subspan(offset, sizeof(EthernetHeader)));
        this->networkProtocol = static_cast<EthernetHeader*>(linkHeader)->etherType;
        std::cout << "\n\033[41mEthernet:\033[0m\n" << *static_cast<EthernetHeader*>(linkHeader) << '\n';
        offset += sizeof(EthernetHeader);
    }
    else // is Loopback header
    {
        this->networkProtocol = IPV4;
        std::cout << "\n\033[41mLoopback:\033[0m\n" << tempHeader << '\n';
        offset += sizeof(LoopbackHeader);
    }

    // Parse NETWORK layer
    if (this->networkProtocol == IPV4)
    {
        this->networkHeader = new IPv4Header(rawData.subspan(offset, sizeof(IPv4Header)));
        offset += sizeof(IPv4Header);
        this->transportProtocol = static_cast<IPv4Header*>(networkHeader)->protocol;
        std::cout << "\033[42mIP:\033[0m\n" << *static_cast<IPv4Header*>(networkHeader) << '\n';
    }
    else if (this->networkProtocol == ARP)
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
        std::cout << "\033[44mDNS (header):\033[0m\n" << static_cast<DNSMessage*>(applicationData)->header;
    }
}

Packet::~Packet()
{
    delete linkHeader;
    delete networkHeader;
    delete transportHeader;
    delete applicationData;
}
